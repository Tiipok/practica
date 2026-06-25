#include "engine/brute_force_engine.h"
#include "checker/password_checker.h"
#include "gpu/gpu_checker.h"
#include <chrono>
#include <iostream>

namespace engine {

namespace {

constexpr int kGpuProgressReportInterval = 10;

} // namespace

BruteForceEngine::BruteForceEngine(const std::string& archive_path)
    : archive_path_(archive_path)
    , password_found_(false)
    , total_checks_(0) {}

BruteForceResult BruteForceEngine::run(generator::PasswordGenerator& generator,
                                       int num_threads) {
    password_found_.store(false, std::memory_order_release);
    total_checks_.store(0, std::memory_order_release);
    found_password_.clear();
    worker_stats_.clear();
    worker_stats_.resize(static_cast<size_t>(num_threads));

    for (int i = 0; i < num_threads; ++i) {
        worker_stats_[static_cast<size_t>(i)].thread_id = i;
        worker_stats_[static_cast<size_t>(i)].checks_done = 0;
        worker_stats_[static_cast<size_t>(i)].found_password = false;
    }

    uint64_t total_space = generator.total_space();
    uint64_t chunk_size = total_space / static_cast<uint64_t>(num_threads);
    if (chunk_size == 0) chunk_size = 1;

    auto t_global_start = std::chrono::high_resolution_clock::now();
    threads_.reserve(static_cast<size_t>(num_threads));

    for (int i = 0; i < num_threads; ++i) {
        uint64_t start = static_cast<uint64_t>(i) * chunk_size;
        uint64_t end = (i == num_threads - 1) ? total_space : start + chunk_size;

        threads_.emplace_back([this, i, start, end, &generator]() {
            auto t_start = std::chrono::high_resolution_clock::now();

            generator::PasswordGenerator gen_copy = generator;
            gen_copy.set_range(start, end);

            checker::PasswordChecker checker(archive_path_);

            while (true) {
                if (password_found_.load(std::memory_order_acquire)) {
                    break;
                }

                auto pw_opt = gen_copy.next();
                if (!pw_opt) {
                    break;
                }

                total_checks_.fetch_add(1, std::memory_order_relaxed);
                worker_stats_[static_cast<size_t>(i)].checks_done++;

                if (checker.check(*pw_opt)) {
                    password_found_.store(true, std::memory_order_release);
                    {
                        std::lock_guard<std::mutex> lock(found_mutex_);
                        if (found_password_.empty()) {
                            found_password_ = *pw_opt;
                            worker_stats_[static_cast<size_t>(i)].found_password = true;
                        }
                    }
                    break;
                }
            }

            auto t_end = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double, std::milli>(t_end - t_start).count();
            worker_stats_[static_cast<size_t>(i)].elapsed_ms = elapsed;
            uint64_t chk = worker_stats_[static_cast<size_t>(i)].checks_done;
            worker_stats_[static_cast<size_t>(i)].checks_per_second =
                (elapsed > 0) ? (chk / (elapsed / 1000.0)) : 0.0;
        });
    }

    for (auto& t : threads_) {
        if (t.joinable()) {
            t.join();
        }
    }
    threads_.clear();

    auto t_global_end = std::chrono::high_resolution_clock::now();
    double global_elapsed = std::chrono::duration<double, std::milli>(
        t_global_end - t_global_start).count();

    BruteForceResult result;
    result.found = password_found_.load(std::memory_order_acquire);
    result.password = found_password_;
    result.total_checks = total_checks_.load(std::memory_order_acquire);
    result.total_elapsed_ms = global_elapsed;
    result.checks_per_second = (global_elapsed > 0)
        ? (result.total_checks / (global_elapsed / 1000.0))
        : 0.0;
    result.num_threads = num_threads;
    result.worker_stats = worker_stats_;
    result.total_space_size = total_space;
    result.gpu_used = false;

    return result;
}

BruteForceResult BruteForceEngine::run_gpu(
    generator::PasswordGenerator& generator,
    size_t batch_size,
    const std::string& known_password) {

    BruteForceResult result;
    result.found = false;
    result.total_checks = 0;
    result.total_elapsed_ms = 0;
    result.checks_per_second = 0;
    result.num_threads = 1;
    result.total_space_size = generator.total_space();
    result.gpu_used = true;

    gpu::GpuChecker gpu_checker(archive_path_, known_password);
    if (!gpu_checker.is_available()) {
        std::cerr << "[GPU] GPU zipcrypto checker unavailable, falling back to CPU"
                  << std::endl;
        result.gpu_used = false;
        return result;
    }

    checker::PasswordChecker verify_checker(archive_path_);
    auto t_start = std::chrono::high_resolution_clock::now();

    uint64_t cumulative_checks = 0;
    size_t batch_idx = 0;

    while (true) {
        std::vector<std::string> batch;
        batch.reserve(batch_size);

        for (size_t i = 0; i < batch_size; ++i) {
            auto pw_opt = generator.next();
            if (!pw_opt) break;
            batch.push_back(std::move(*pw_opt));
        }

        if (batch.empty()) break;

        ++batch_idx;
        cumulative_checks += batch.size();

        std::string gpu_found;
        bool gpu_hit = gpu_checker.check_batch(batch, gpu_found);

        if (gpu_hit) {
            generator.reset_to(generator.password_to_index(gpu_found));

            if (verify_checker.check(gpu_found)) {
                result.found = true;
                result.password = gpu_found;
                break;
            }

            generator.reset_to(generator.password_to_index(gpu_found) + 1);
        }

        if (batch_idx % kGpuProgressReportInterval == 0) {
            double elapsed = std::chrono::duration<double, std::milli>(
                std::chrono::high_resolution_clock::now() - t_start).count();
            double speed = elapsed > 0 ? (cumulative_checks / (elapsed / 1000.0)) : 0;
            std::cout << "  [GPU] batch " << batch_idx
                      << "  checked " << cumulative_checks
                      << "  speed " << static_cast<uint64_t>(speed) << "/s\r"
                      << std::flush;
        }
    }

    auto t_end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::milli>(t_end - t_start).count();
    result.total_checks = cumulative_checks;
    result.total_elapsed_ms = elapsed;
    result.checks_per_second = (elapsed > 0)
        ? (cumulative_checks / (elapsed / 1000.0)) : 0.0;

    WorkerStats ws;
    ws.thread_id = 0;
    ws.checks_done = result.total_checks;
    ws.elapsed_ms = elapsed;
    ws.checks_per_second = result.checks_per_second;
    ws.found_password = result.found;
    result.worker_stats.push_back(ws);

    return result;
}

} // namespace engine
