#pragma once

#include "app/cli_parser.h"
#include "archive/archive_manager.h"
#include "generator/charset.h"
#include "storage/results_storage.h"
#include <string>
#include <vector>

namespace app {

class ExperimentRunner {
public:
    explicit ExperimentRunner(const ExperimentConfig& config);

    void run_single_experiment(const std::string& archive_path,
                                const std::string& known_password,
                                const archive::EncryptionType& encryption,
                                int archive_size,
                                const std::string& archive_name);

    void run_thread_comparison(const std::string& archive_path,
                                const std::string& known_password,
                                const archive::EncryptionType& encryption,
                                int archive_size,
                                const std::string& archive_name,
                                const std::vector<int>& thread_counts);

    void run_full_matrix();
    void run_benchmarks();
    void run_all();

private:
    void run_single_with_threads(const std::string& archive_path,
                                  const std::string& known_password,
                                  size_t password_length,
                                  const std::string& charset_name,
                                  const charset::Charset& ch,
                                  const std::string& protection_type,
                                  int archive_size,
                                  const std::string& archive_name,
                                  int num_threads);

    ExperimentConfig config_;
    storage::ResultsStorage storage_;
    std::string compiler_flags_;
    std::string cpu_model_;
};

} // namespace app
