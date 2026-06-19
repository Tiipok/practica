#pragma once

#include <chrono>
#include <cstdint>
#include <mach/mach.h>
#include <string>

namespace stats {

struct MemoryUsage {
    uint64_t resident_bytes;
    uint64_t virtual_bytes;
};

struct PerformanceMetrics {
    int num_threads;
    uint64_t total_checks;
    double total_elapsed_ms;
    double checks_per_second;
    double cpu_load_percent;
    MemoryUsage peak_memory;
    size_t password_length;
    std::string charset_name;
    size_t charset_size;
    uint64_t total_space_size;
    double space_coverage_percent;
};

class StatsCollector {
public:
    StatsCollector();

    void start();
    void stop();

    double elapsed_ms() const;
    double elapsed_seconds() const;

    static MemoryUsage current_memory();
    static double cpu_load_percent();

    PerformanceMetrics build_metrics(int num_threads,
                                      uint64_t total_checks,
                                      size_t password_length,
                                      const std::string& charset_name,
                                      size_t charset_size,
                                      uint64_t total_space_size);

private:
    std::chrono::high_resolution_clock::time_point start_time_;
    std::chrono::high_resolution_clock::time_point end_time_;
    bool running_;
};

} // namespace stats
