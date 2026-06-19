#include "app/cli_parser.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace app {

std::optional<ExperimentConfig> CliParser::parse(int argc, char* argv[]) {
    ExperimentConfig config;
    config.charset_type = charset::Type::DIGITS;
    config.min_length = 1;
    config.max_length = 5;
    config.num_threads = 0;
    config.run_matrix = false;
    config.skip_test_suite = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return std::nullopt;
        } else if (arg == "--archive" && i + 1 < argc) {
            config.archive_path = argv[++i];
        } else if (arg == "--output-dir" && i + 1 < argc) {
            config.output_dir = argv[++i];
        } else if (arg == "--charset" && i + 1 < argc) {
            std::string cs = argv[++i];
            if (cs == "digits") config.charset_type = charset::Type::DIGITS;
            else if (cs == "lowercase") config.charset_type = charset::Type::LOWERCASE;
            else if (cs == "alphanum") config.charset_type = charset::Type::ALPHANUM;
            else {
                std::cerr << "Unknown charset: " << cs << std::endl;
                return std::nullopt;
            }
        } else if (arg == "--min-len" && i + 1 < argc) {
            config.min_length = static_cast<size_t>(std::stoul(argv[++i]));
        } else if (arg == "--max-len" && i + 1 < argc) {
            config.max_length = static_cast<size_t>(std::stoul(argv[++i]));
        } else if (arg == "--threads" && i + 1 < argc) {
            std::string t = argv[++i];
            if (t == "auto") {
                config.num_threads = 0;
            } else {
                config.num_threads = std::stoi(t);
            }
        } else if (arg == "--thread-counts" && i + 1 < argc) {
            std::string counts = argv[++i];
            config.thread_counts.clear();
            size_t pos = 0;
            while (pos < counts.size()) {
                size_t comma = counts.find(',', pos);
                std::string num = counts.substr(pos, comma - pos);
                config.thread_counts.push_back(std::stoi(num));
                pos = (comma == std::string::npos) ? counts.size() : comma + 1;
            }
        } else if (arg == "--matrix") {
            config.run_matrix = true;
        } else if (arg == "--skip-test-suite") {
            config.skip_test_suite = true;
        } else if (arg == "--source-file" && i + 1 < argc) {
            config.source_file = argv[++i];
        }
    }

    if (config.output_dir.empty()) {
        config.output_dir = "results";
    }
    if (config.archive_path.empty() && !config.run_matrix && config.skip_test_suite) {
        std::cerr << "Error: --archive or --matrix is required when skipping test suite" << std::endl;
        return std::nullopt;
    }

    if (config.max_length > charset::kMaxPasswordLength) {
        std::cerr << "Error: max password length cannot exceed "
                  << static_cast<int>(charset::kMaxPasswordLength) << std::endl;
        return std::nullopt;
    }

    if (config.min_length > config.max_length) {
        std::cerr << "Error: min-len cannot exceed max-len" << std::endl;
        return std::nullopt;
    }

    return config;
}

void CliParser::print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n\n"
              << "ZIP Password Bruteforce Research Tool\n"
              << "Apple Silicon M4 Optimized\n\n"
              << "Options:\n"
              << "  --archive <path>       Path to test ZIP archive\n"
              << "  --output-dir <dir>     Output directory for results (default: results)\n"
              << "  --charset <type>       Password charset: digits|lowercase|alphanum\n"
              << "                         (default: digits)\n"
              << "  --min-len <n>          Minimum password length (default: 1)\n"
              << "  --max-len <n>          Maximum password length (default: 5, max: 5)\n"
              << "  --threads <n|auto>     Number of threads, 0 or auto for hardware concurrency\n"
              << "  --thread-counts <n1,n2,...>  Comma-separated thread counts for comparison\n"
              << "  --matrix               Run full experiment matrix\n"
              << "  --skip-test-suite      Skip creating test archive suite\n"
              << "  --source-file <path>   Source file for creating test archives\n"
              << "  --help, -h             Show this help\n"
              << std::endl;
}

} // namespace app
