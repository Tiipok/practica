#pragma once

#include "generator/charset.h"
#include <string>
#include <vector>
#include <optional>

namespace app {

struct ExperimentConfig {
    std::string archive_path;
    std::string output_dir;
    charset::Type charset_type;
    size_t min_length;
    size_t max_length;
    int num_threads;
    std::vector<int> thread_counts;
    bool run_matrix;
    bool skip_test_suite;
    std::string source_file;
};

class CliParser {
public:
    static std::optional<ExperimentConfig> parse(int argc, char* argv[]);
    static void print_usage(const char* program_name);
};

} // namespace app
