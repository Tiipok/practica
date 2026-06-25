#include "app/experiment_runner.h"
#include "archive/archive_manager.h"
#include "engine/brute_force_engine.h"
#include "generator/password_generator.h"
#include "stats/stats_collector.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sys/sysctl.h>

namespace app {

namespace {

constexpr uint64_t kMaxMatrixSpaceSize = 10'000'000;
constexpr size_t kDefaultGpuBatchSize = 65536;

int resolve_thread_count(int configured_threads) {
    if (configured_threads <= 0) {
        return static_cast<int>(std::thread::hardware_concurrency());
    }
    return configured_threads;
}

charset::Charset detect_charset_for_password(const std::string& password) {
    bool has_lower = false;
    bool has_digit = false;
    for (char c : password) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        else if (c >= '0' && c <= '9') has_digit = true;
    }

    if (has_digit && !has_lower) {
        return charset::Charset::digits();
    } else if (has_lower && !has_digit) {
        return charset::Charset::lowercase();
    }
    return charset::Charset::alphanum();
}

std::string detect_charset_name_for_password(const std::string& password) {
    bool has_lower = false;
    bool has_digit = false;
    for (char c : password) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        else if (c >= '0' && c <= '9') has_digit = true;
    }

    if (has_digit && !has_lower) return "digits";
    if (has_lower && !has_digit) return "lowercase";
    return "alphanum";
}

std::string fetch_cpu_model() {
    char cpu_brand[256];
    size_t size = sizeof(cpu_brand);
    if (sysctlbyname("machdep.cpu.brand_string", &cpu_brand, &size, nullptr, 0) == 0) {
        return cpu_brand;
    }
    return "Apple Silicon (unknown)";
}

void create_default_source_file(const std::string& path) {
    std::ofstream src(path);
    src << "Test file for ZIP bruteforce research.\n"
        << "Apple Silicon M4 Performance Analysis\n"
        << "Created: " << __DATE__ << " " << __TIME__ << "\n";
}

} // namespace

ExperimentRunner::ExperimentRunner(const ExperimentConfig& config)
    : config_(config)
    , storage_(config.output_dir + "/experiments.db")
{
    std::filesystem::create_directories(config_.output_dir);
    storage_.initialize();

#ifdef NDEBUG
    compiler_flags_ = "Release -O3 -DNDEBUG";
#else
    compiler_flags_ = "Debug -O0 -g";
#endif

    cpu_model_ = fetch_cpu_model();
}

void ExperimentRunner::run_single_with_threads(
    const std::string& archive_path,
    const std::string& known_password,
    size_t password_length,
    const std::string& charset_name,
    const charset::Charset& ch,
    const std::string& protection_type,
    int archive_size,
    const std::string& archive_name,
    int num_threads) {

    generator::PasswordGenerator gen(ch, password_length, password_length);
    uint64_t total_space = gen.total_space();

    std::cout << "\n  Running with " << num_threads << " thread(s), "
              << "charset=" << charset_name
              << " (size=" << ch.size() << "), "
              << "password length=" << password_length
              << ", protection=" << protection_type << std::endl;

    std::cout << "  Password space size: " << total_space << std::endl;

    stats::StatsCollector collector;
    collector.start();

    engine::BruteForceEngine engine(archive_path);

    engine::BruteForceResult result;
    if (config_.use_gpu) {
        result = engine.run_gpu(gen, kDefaultGpuBatchSize, known_password);
        if (!result.gpu_used) {
            result = engine.run(gen, num_threads);
        }
    } else {
        result = engine.run(gen, num_threads);
    }

    collector.stop();

    double elapsed_ms = collector.elapsed_ms();

    if (result.found) {
        std::cout << "  Password found: " << result.password
                  << " after " << result.total_checks << " checks in "
                  << elapsed_ms << " ms" << std::endl;
    } else {
        std::cout << "  Password NOT found after " << result.total_checks
                  << " checks in " << elapsed_ms << " ms" << std::endl;
    }

    std::cout << "  Speed: " << result.checks_per_second << " checks/sec" << std::endl;

    auto metrics = collector.build_metrics(
        num_threads, result.total_checks, password_length,
        charset_name, ch.size(), total_space);

    archive::ArchiveInfo archive_info;
    archive_info.name = archive_name;
    archive_info.path = archive_path;
    archive_info.password = result.password;
    archive_info.password_length = password_length;
    archive_info.charset_name = charset_name;
    archive_info.encryption = (protection_type == "AES-256")
        ? archive::EncryptionType::AES_256
        : archive::EncryptionType::ZIP_CRYPTO;
    archive_info.archive_size_bytes = archive_size;
    archive_info.original_size_bytes = 0;

    auto record = storage_.build_record(archive_info, result, metrics,
                                         compiler_flags_, cpu_model_,
                                         config_.use_gpu ? "GPU" : "CPU");
    int id = storage_.save_result(record);
    std::cout << "  Saved as experiment #" << id << std::endl;
}

void ExperimentRunner::run_single_experiment(const std::string& archive_path,
                                              const std::string& known_password,
                                              const archive::EncryptionType& encryption,
                                              int archive_size,
                                              const std::string& archive_name) {
    auto ch = detect_charset_for_password(known_password);
    std::string charset_name = detect_charset_name_for_password(known_password);
    std::string protection = archive::encryption_type_name(encryption);
    int threads = resolve_thread_count(config_.num_threads);

    run_single_with_threads(archive_path, known_password,
                             known_password.length(), charset_name, ch,
                             protection, archive_size, archive_name, threads);
}

void ExperimentRunner::run_thread_comparison(
    const std::string& archive_path,
    const std::string& known_password,
    const archive::EncryptionType& encryption,
    int archive_size,
    const std::string& archive_name,
    const std::vector<int>& thread_counts) {

    auto ch = charset::Charset::from_type(config_.charset_type);
    std::string charset_name = charset::type_name(config_.charset_type);
    std::string protection = archive::encryption_type_name(encryption);

    for (int tc : thread_counts) {
        run_single_with_threads(archive_path, known_password,
                                 config_.max_length, charset_name, ch,
                                 protection, archive_size, archive_name, tc);
    }
}

void ExperimentRunner::run_full_matrix() {
    std::cout << "=== Running Full Experiment Matrix ===" << std::endl;

    auto ch = charset::Charset::from_type(config_.charset_type);
    std::string charset_name = charset::type_name(config_.charset_type);

    std::vector<int> thread_counts = {1, 2, 4, 6, 10};
    if (!config_.thread_counts.empty()) {
        thread_counts = config_.thread_counts;
    }

    for (size_t length = config_.min_length; length <= config_.max_length; ++length) {
        generator::PasswordGenerator gen(ch, length, length);
        uint64_t space_size = gen.total_space();

        if (space_size > kMaxMatrixSpaceSize) {
            std::cout << "  Skipping length " << length
                      << " (space size " << space_size << " too large for full scan)" << std::endl;
            continue;
        }

        std::cout << "\n--- Length " << length << ", Space " << space_size << " ---" << std::endl;

        for (int tc : thread_counts) {
            generator::PasswordGenerator thread_gen(ch, length, length);

            stats::StatsCollector collector;
            collector.start();

            engine::BruteForceEngine engine(config_.archive_path);
            auto result = engine.run(thread_gen, tc);

            collector.stop();

            auto metrics = collector.build_metrics(tc, result.total_checks,
                                                    length, charset_name,
                                                    ch.size(), thread_gen.total_space());

            archive::ArchiveInfo archive_info;
            archive_info.name = "matrix_test";
            archive_info.path = config_.archive_path;
            archive_info.password_length = length;
            archive_info.charset_name = charset_name;

            auto record = storage_.build_record(archive_info, result, metrics,
                                                 compiler_flags_, cpu_model_, "CPU");
            storage_.save_result(record);

            std::cout << "  threads=" << tc
                      << " checks=" << result.total_checks
                      << " time=" << result.total_elapsed_ms << "ms"
                      << " speed=" << result.checks_per_second << "/s" << std::endl;
        }
    }

    std::cout << "\nMatrix complete. Exporting CSV..." << std::endl;
    storage_.export_csv(config_.output_dir + "/results.csv");
}

void ExperimentRunner::run_benchmarks() {
    std::cout << "=== Running Automated Benchmarks ===\n"
              << "Mode: " << config_.benchmark_mode
              << ", Repeat: " << config_.repeat_count << "\n"
              << std::endl;

    std::string source_file = config_.source_file;
    if (source_file.empty()) {
        std::filesystem::create_directories(config_.output_dir);
        source_file = config_.output_dir + "/bench_source.txt";
        create_default_source_file(source_file);
    }

    std::string bench_data_dir = config_.output_dir + "/bench_data";
    std::filesystem::create_directories(bench_data_dir);

    auto archives = archive::ArchiveManager::create_benchmark_suite(
        bench_data_dir, source_file, config_.max_length, config_.random_seed);

    std::cout << "Created " << archives.size() << " benchmark archives\n" << std::endl;

    std::vector<int> cpu_thread_counts = {1, 2, 4, 6, 8, 10};
    bool run_cpu = (config_.benchmark_mode == "cpu" || config_.benchmark_mode == "both");
    bool run_gpu = (config_.benchmark_mode == "gpu" || config_.benchmark_mode == "both");

    for (int rep = 0; rep < config_.repeat_count; ++rep) {
        std::cout << "--- Repeat " << (rep + 1) << "/"
                  << config_.repeat_count << " ---" << std::endl;

        for (const auto& arch : archives) {
            auto ch = charset::Charset::from_type(
                charset::Type::DIGITS);
            if (arch.charset_name == "lowercase") {
                ch = charset::Charset::lowercase();
            } else if (arch.charset_name == "alphanum") {
                ch = charset::Charset::alphanum();
            }

            std::string protection = archive::encryption_type_name(arch.encryption);

            if (run_cpu) {
                for (int tc : cpu_thread_counts) {
                    run_single_with_threads(arch.path, arch.password,
                                             arch.password_length, arch.charset_name,
                                             ch, protection,
                                             static_cast<int>(arch.archive_size_bytes),
                                             arch.name, tc);
                }
            }

            if (run_gpu) {
                generator::PasswordGenerator gen(
                    ch, arch.password_length, arch.password_length);
                uint64_t total_space = gen.total_space();

                stats::StatsCollector collector;
                collector.start();
                engine::BruteForceEngine engine(arch.path);
                auto result = engine.run_gpu(gen, kDefaultGpuBatchSize, arch.password);
                collector.stop();

                if (result.gpu_used && result.found) {
                    double elapsed = collector.elapsed_ms();
                    std::cout << "  GPU found: " << result.password
                              << " checks=" << result.total_checks
                              << " time=" << elapsed << "ms"
                              << " speed=" << result.checks_per_second << "/s" << std::endl;

                    auto metrics = collector.build_metrics(
                        1, result.total_checks, arch.password_length,
                        arch.charset_name, ch.size(), total_space);

                    auto record = storage_.build_record(
                        arch, result, metrics, compiler_flags_, cpu_model_,
                        result.gpu_used ? "GPU" : "CPU");
                    storage_.save_result(record);
                } else {
                    std::cout << "  GPU FAILED for " << arch.name << std::endl;
                }
            }
        }
    }

    std::cout << "\n=== Benchmarks Complete ===\nExporting CSV..." << std::endl;
    storage_.export_csv(config_.output_dir + "/results.csv");
    std::cout << "Results: " << config_.output_dir << "/results.csv" << std::endl;
    std::cout << "Database: " << config_.output_dir << "/experiments.db" << std::endl;
}

void ExperimentRunner::run_all() {
    if (!config_.skip_test_suite) {
        std::cout << "=== Creating Test Archive Suite ===" << std::endl;

        std::string source_file = config_.source_file;
        if (source_file.empty()) {
            source_file = config_.output_dir + "/test_source.txt";
            create_default_source_file(source_file);
        }

        std::string test_data_dir = config_.output_dir + "/test_data";
        std::filesystem::create_directories(test_data_dir);

        auto archives = archive::ArchiveManager::create_test_suite(test_data_dir, source_file);

        std::cout << "Created " << archives.size() << " test archives:\n";
        for (const auto& info : archives) {
            std::cout << "  " << info.name
                      << " | password: " << info.password
                      << " | " << archive::encryption_type_name(info.encryption)
                      << " | " << info.archive_size_bytes << " bytes\n";
        }

        std::cout << "\n=== Running Experiments on Test Suite ===" << std::endl;

        for (const auto& arch_info : archives) {
            std::cout << "\n--- Testing: " << arch_info.name << " ---" << std::endl;
            run_single_experiment(arch_info.path, arch_info.password,
                                   arch_info.encryption,
                                   static_cast<int>(arch_info.archive_size_bytes),
                                   arch_info.name);
        }
    }

    if (config_.run_matrix) {
        run_full_matrix();
    } else if (!config_.archive_path.empty()) {
        int threads = resolve_thread_count(config_.num_threads);

        if (!config_.thread_counts.empty()) {
            run_thread_comparison(
                config_.archive_path, "", archive::EncryptionType::ZIP_CRYPTO,
                0, "single_archive", config_.thread_counts);
        } else {
            std::cout << "\n--- Testing: " << config_.archive_path << " ---" << std::endl;
            auto ch = charset::Charset::from_type(config_.charset_type);
            auto charset_name = charset::type_name(config_.charset_type);
            run_single_with_threads(config_.archive_path, "",
                                     config_.max_length, charset_name, ch,
                                     "ZipCrypto", 0, config_.archive_path, threads);
        }
    }

    std::cout << "\n=== All Experiments Complete ===" << std::endl;
    storage_.export_csv(config_.output_dir + "/results.csv");
    std::cout << "Results saved to: " << config_.output_dir << "/results.csv" << std::endl;
    std::cout << "Database saved to: " << config_.output_dir << "/experiments.db" << std::endl;
}

} // namespace app
