#include "app/experiment_runner.h"
#include "archive/archive_manager.h"
#include <cmath>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sys/sysctl.h>

namespace app {

ExperimentRunner::ExperimentRunner(const ExperimentConfig& config)
    : config_(config)
    , storage_(config.output_dir + "/experiments.db")
{
    storage_.initialize();

#ifdef NDEBUG
    compiler_flags_ = "Release -O3 -DNDEBUG";
#else
    compiler_flags_ = "Debug -O0 -g";
#endif

    char cpu_brand[256];
    size_t size = sizeof(cpu_brand);
    if (sysctlbyname("machdep.cpu.brand_string", &cpu_brand, &size, nullptr, 0) == 0) {
        cpu_model_ = cpu_brand;
    } else {
        cpu_model_ = "Apple Silicon (unknown)";
    }
}

void ExperimentRunner::run_single_with_threads(
    const std::string& archive_path,
    const std::string& /*known_password*/,
    size_t password_length,
    const std::string& charset_name,
    const charset::Charset& ch,
    const std::string& protection_type,
    int archive_size,
    const std::string& archive_name,
    int num_threads) {

    std::cout << "\n  Running with " << num_threads << " thread(s), "
              << "charset=" << charset_name
              << " (size=" << ch.size() << "), "
              << "password length=" << password_length
              << ", protection=" << protection_type << std::endl;

    generator::PasswordGenerator gen(ch, password_length, password_length);

    uint64_t total_space = gen.total_space();
    std::cout << "  Password space size: " << total_space << std::endl;

    stats::StatsCollector collector;
    collector.start();

    engine::BruteForceEngine engine(archive_path);
    auto result = engine.run(gen, num_threads);

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

    archive::ArchiveInfo arch_info;
    arch_info.name = archive_name;
    arch_info.path = archive_path;
    arch_info.password = result.password;
    arch_info.password_length = password_length;
    arch_info.charset_name = charset_name;
    arch_info.encryption = (protection_type == "AES-256")
        ? archive::EncryptionType::AES_256
        : archive::EncryptionType::ZIP_CRYPTO;
    arch_info.archive_size_bytes = archive_size;
    arch_info.original_size_bytes = 0;

    auto record = storage_.build_record(arch_info, result, metrics,
                                         compiler_flags_, cpu_model_);
    int id = storage_.save_result(record);
    std::cout << "  Saved as experiment #" << id << std::endl;
}

void ExperimentRunner::run_single_experiment(const std::string& archive_path,
                                              const std::string& known_password,
                                              const archive::EncryptionType& encryption,
                                              int archive_size,
                                              const std::string& archive_name) {
    auto ch = charset::Charset::digits();
    charset::Type cs_type = charset::Type::DIGITS;

    bool has_lower = false, has_digit = false;
    for (char c : known_password) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        else if (c >= '0' && c <= '9') has_digit = true;
    }

    if (has_digit && !has_lower) {
        ch = charset::Charset::digits();
        cs_type = charset::Type::DIGITS;
    } else if (has_lower && !has_digit) {
        ch = charset::Charset::lowercase();
        cs_type = charset::Type::LOWERCASE;
    } else {
        ch = charset::Charset::alphanum();
        cs_type = charset::Type::ALPHANUM;
    }

    std::string charset_name = charset::type_name(cs_type);
    std::string protection = archive::encryption_type_name(encryption);

    int threads = config_.num_threads;
    if (threads <= 0) {
        threads = static_cast<int>(std::thread::hardware_concurrency());
    }

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
        uint64_t space_size = 0;
        size_t base = ch.size();
        uint64_t accum = 1;
        for (size_t i = 0; i < length; ++i) accum *= base;
        space_size = accum;

        if (space_size > 10'000'000) {
            std::cout << "  Skipping length " << length
                      << " (space size " << space_size << " too large for full scan)" << std::endl;
            continue;
        }

        std::cout << "\n--- Length " << length << ", Space " << space_size << " ---" << std::endl;

        for (int tc : thread_counts) {
            generator::PasswordGenerator gen(ch, length, length);

            stats::StatsCollector collector;
            collector.start();

            engine::BruteForceEngine engine(config_.archive_path);
            auto result = engine.run(gen, tc);

            collector.stop();

            auto metrics = collector.build_metrics(tc, result.total_checks,
                                                    length, charset_name,
                                                    ch.size(), gen.total_space());

            archive::ArchiveInfo arch_info;
            arch_info.name = "matrix_test";
            arch_info.path = config_.archive_path;
            arch_info.password_length = length;
            arch_info.charset_name = charset_name;

            auto record = storage_.build_record(arch_info, result, metrics,
                                                 compiler_flags_, cpu_model_);
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

void ExperimentRunner::run_all() {
    if (!config_.skip_test_suite) {
        std::cout << "=== Creating Test Archive Suite ===" << std::endl;

        std::string source_file = config_.source_file;
        if (source_file.empty()) {
            source_file = config_.output_dir + "/test_source.txt";
            std::ofstream src(source_file);
            src << "This is a test file for ZIP bruteforce research.\n"
                << "Apple Silicon M4 Performance Analysis\n"
                << "Created: " << __DATE__ << " " << __TIME__ << "\n";
            src.close();
        }

        std::string test_data_dir = config_.output_dir + "/test_data";
        std::system(("mkdir -p " + test_data_dir).c_str());

        auto archives = archive::ArchiveManager::create_test_suite(test_data_dir, source_file);

        std::cout << "Created " << archives.size() << " test archives:\n";
        for (const auto& info : archives) {
            std::cout << "  " << info.name
                      << " | password: " << info.password
                      << " | " << archive::encryption_type_name(info.encryption)
                      << " | " << info.archive_size_bytes << " bytes\n";
        }

        std::cout << "\n=== Running Experiments on Test Suite ===" << std::endl;

        int threads = config_.num_threads;
        if (threads <= 0) {
            threads = static_cast<int>(std::thread::hardware_concurrency());
        }

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
        int threads = config_.num_threads;
        if (threads <= 0) {
            threads = static_cast<int>(std::thread::hardware_concurrency());
        }

        if (!config_.thread_counts.empty()) {
            run_thread_comparison(
                config_.archive_path, "", archive::EncryptionType::ZIP_CRYPTO,
                0, "single_archive", config_.thread_counts);
        } else {
            std::cout << "\n--- Testing: " << config_.archive_path << " ---" << std::endl;
            run_single_experiment(config_.archive_path, "",
                                   archive::EncryptionType::ZIP_CRYPTO,
                                   0, config_.archive_path);
        }
    }

    std::cout << "\n=== All Experiments Complete ===" << std::endl;
    storage_.export_csv(config_.output_dir + "/results.csv");
    std::cout << "Results saved to: " << config_.output_dir << "/results.csv" << std::endl;
    std::cout << "Database saved to: " << config_.output_dir << "/experiments.db" << std::endl;
}

} // namespace app
