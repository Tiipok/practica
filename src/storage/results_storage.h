#pragma once

#include "engine/brute_force_engine.h"
#include "stats/stats_collector.h"
#include "archive/archive_manager.h"
#include <cstdint>
#include <string>
#include <vector>

struct sqlite3;

namespace storage {

struct ExperimentRecord {
    int id;
    std::string timestamp;
    std::string archive_name;
    std::string archive_path;
    int64_t archive_size_bytes;
    std::string protection_type;
    std::string charset_name;
    size_t charset_size;
    size_t password_length;
    uint64_t total_space_size;
    int num_threads;
    uint64_t total_checks;
    double total_time_ms;
    double checks_per_second;
    double cpu_load_percent;
    uint64_t memory_resident_bytes;
    uint64_t memory_virtual_bytes;
    std::string compiler_flags;
    std::string cpu_model;
    bool password_found;
    std::string found_password;
};

class ResultsStorage {
public:
    explicit ResultsStorage(const std::string& db_path);
    ~ResultsStorage();

    void initialize();

    int save_result(const ExperimentRecord& record);
    std::vector<ExperimentRecord> load_all();
    std::vector<ExperimentRecord> load_by_archive(const std::string& archive_name);
    bool export_csv(const std::string& csv_path);

    ExperimentRecord build_record(
        const archive::ArchiveInfo& archive_info,
        const engine::BruteForceResult& engine_result,
        const stats::PerformanceMetrics& metrics,
        const std::string& compiler_flags,
        const std::string& cpu_model);

private:
    sqlite3* db_;
    std::string db_path_;
};

} // namespace storage
