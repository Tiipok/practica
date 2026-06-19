#pragma once

#include "generator/password_generator.h"
#include "checker/password_checker.h"
#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace engine {

struct WorkerStats {
    int thread_id;
    uint64_t checks_done;
    double elapsed_ms;
    double checks_per_second;
    bool found_password;
};

struct BruteForceResult {
    bool found;
    std::string password;
    uint64_t total_checks;
    double total_elapsed_ms;
    double checks_per_second;
    int num_threads;
    std::vector<WorkerStats> worker_stats;
    uint64_t total_space_size;
};

class BruteForceEngine {
public:
    explicit BruteForceEngine(const std::string& archive_path);

    BruteForceResult run(generator::PasswordGenerator& generator,
                        int num_threads);

private:
    void worker_func(int thread_id,
                     uint64_t range_start,
                     uint64_t range_end,
                     const generator::PasswordGenerator& gen_template,
                     WorkerStats& stats);

    std::string archive_path_;
    std::atomic<bool> password_found_;
    std::atomic<uint64_t> total_checks_;
    std::string found_password_;
    std::mutex found_mutex_;
    std::vector<std::thread> threads_;
    std::vector<WorkerStats> worker_stats_;
};

} // namespace engine
