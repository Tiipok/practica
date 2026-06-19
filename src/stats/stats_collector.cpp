#include "stats/stats_collector.h"

namespace stats {

StatsCollector::StatsCollector() : running_(false) {}

void StatsCollector::start() {
    start_time_ = std::chrono::high_resolution_clock::now();
    running_ = true;
}

void StatsCollector::stop() {
    end_time_ = std::chrono::high_resolution_clock::now();
    running_ = false;
}

double StatsCollector::elapsed_ms() const {
    auto end = running_ ? std::chrono::high_resolution_clock::now() : end_time_;
    return std::chrono::duration<double, std::milli>(end - start_time_).count();
}

double StatsCollector::elapsed_seconds() const {
    return elapsed_ms() / 1000.0;
}

MemoryUsage StatsCollector::current_memory() {
    struct task_basic_info t_info;
    mach_msg_type_number_t t_info_count = TASK_BASIC_INFO_COUNT;

    MemoryUsage mem{0, 0};
    if (task_info(mach_task_self(), TASK_BASIC_INFO,
                  reinterpret_cast<task_info_t>(&t_info),
                  &t_info_count) == KERN_SUCCESS) {
        mem.resident_bytes = t_info.resident_size;
        mem.virtual_bytes = t_info.virtual_size;
    }
    return mem;
}

double StatsCollector::cpu_load_percent() {
    thread_array_t thread_list;
    mach_msg_type_number_t thread_count;
    double total_cpu = 0.0;

    kern_return_t kr = task_threads(mach_task_self(), &thread_list, &thread_count);
    if (kr != KERN_SUCCESS) return 0.0;

    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        thread_basic_info_data_t basic_info;
        mach_msg_type_number_t bi_count = THREAD_BASIC_INFO_COUNT;

        kr = thread_info(thread_list[i], THREAD_BASIC_INFO,
                         reinterpret_cast<thread_info_t>(&basic_info),
                         &bi_count);
        if (kr == KERN_SUCCESS) {
            if (basic_info.flags & TH_FLAGS_IDLE) continue;
            total_cpu += static_cast<double>(basic_info.cpu_usage)
                         / static_cast<double>(TH_USAGE_SCALE) * 100.0;
        }
    }

    vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(thread_list),
                  thread_count * sizeof(thread_t));

    return total_cpu;
}

PerformanceMetrics StatsCollector::build_metrics(
    int num_threads,
    uint64_t total_checks,
    size_t password_length,
    const std::string& charset_name,
    size_t charset_size,
    uint64_t total_space_size) {

    double elapsed = elapsed_ms();

    PerformanceMetrics metrics;
    metrics.num_threads = num_threads;
    metrics.total_checks = total_checks;
    metrics.total_elapsed_ms = elapsed;
    metrics.checks_per_second = (elapsed > 0)
        ? (static_cast<double>(total_checks) / (elapsed / 1000.0))
        : 0.0;
    metrics.cpu_load_percent = cpu_load_percent();
    metrics.peak_memory = current_memory();
    metrics.password_length = password_length;
    metrics.charset_name = charset_name;
    metrics.charset_size = charset_size;
    metrics.total_space_size = total_space_size;
    metrics.space_coverage_percent = (total_space_size > 0)
        ? (static_cast<double>(total_checks) / static_cast<double>(total_space_size) * 100.0)
        : 0.0;

    return metrics;
}

} // namespace stats
