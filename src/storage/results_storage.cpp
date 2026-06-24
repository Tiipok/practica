#include "storage/results_storage.h"
#include <sqlite3.h>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iostream>
#include <sstream>

namespace storage {

static inline const char* col_text(sqlite3_stmt* stmt, int col) {
    auto* txt = sqlite3_column_text(stmt, col);
    return txt ? reinterpret_cast<const char*>(txt) : "";
}

ResultsStorage::ResultsStorage(const std::string& db_path)
    : db_(nullptr)
    , db_path_(db_path) {}

ResultsStorage::~ResultsStorage() {
    if (db_) {
        sqlite3_close(db_);
    }
}

void ResultsStorage::initialize() {
    int rc = sqlite3_open(db_path_.c_str(), &db_);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to open database: "
                  << (db_ ? sqlite3_errmsg(db_) : "unknown error") << std::endl;
        return;
    }

    const char* create_sql = R"(
        CREATE TABLE IF NOT EXISTS experiments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            archive_name TEXT NOT NULL,
            archive_path TEXT,
            archive_size_bytes INTEGER,
            protection_type TEXT,
            charset_name TEXT,
            charset_size INTEGER,
            password_length INTEGER,
            total_space_size INTEGER,
            num_threads INTEGER,
            total_checks INTEGER,
            total_time_ms REAL,
            checks_per_second REAL,
            cpu_load_percent REAL,
            memory_resident_bytes INTEGER,
            memory_virtual_bytes INTEGER,
            compiler_flags TEXT,
            cpu_model TEXT,
            password_found INTEGER,
            found_password TEXT,
            execution_mode TEXT
        );
    )";

    char* err_msg = nullptr;
    rc = sqlite3_exec(db_, create_sql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to create table: " << err_msg << std::endl;
        sqlite3_free(err_msg);
    }
}

int ResultsStorage::save_result(const ExperimentRecord& record) {
    if (!db_) return -1;

    const char* insert_sql = R"(
        INSERT INTO experiments (
            timestamp, archive_name, archive_path, archive_size_bytes,
            protection_type, charset_name, charset_size, password_length,
            total_space_size, num_threads, total_checks, total_time_ms,
            checks_per_second, cpu_load_percent, memory_resident_bytes,
            memory_virtual_bytes, compiler_flags, cpu_model,
            password_found, found_password, execution_mode
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
    )";

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, insert_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        std::cerr << "Failed to prepare insert: " << sqlite3_errmsg(db_) << std::endl;
        return -1;
    }

    sqlite3_bind_text(stmt, 1, record.timestamp.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, record.archive_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, record.archive_path.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 4, record.archive_size_bytes);
    sqlite3_bind_text(stmt, 5, record.protection_type.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, record.charset_name.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int64(stmt, 7, static_cast<int64_t>(record.charset_size));
    sqlite3_bind_int64(stmt, 8, static_cast<int64_t>(record.password_length));
    sqlite3_bind_int64(stmt, 9, static_cast<int64_t>(record.total_space_size));
    sqlite3_bind_int(stmt, 10, record.num_threads);
    sqlite3_bind_int64(stmt, 11, static_cast<int64_t>(record.total_checks));
    sqlite3_bind_double(stmt, 12, record.total_time_ms);
    sqlite3_bind_double(stmt, 13, record.checks_per_second);
    sqlite3_bind_double(stmt, 14, record.cpu_load_percent);
    sqlite3_bind_int64(stmt, 15, static_cast<int64_t>(record.memory_resident_bytes));
    sqlite3_bind_int64(stmt, 16, static_cast<int64_t>(record.memory_virtual_bytes));
    sqlite3_bind_text(stmt, 17, record.compiler_flags.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 18, record.cpu_model.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 19, record.password_found ? 1 : 0);
    sqlite3_bind_text(stmt, 20, record.found_password.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 21, record.execution_mode.c_str(), -1, SQLITE_TRANSIENT);

    rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);

    if (rc != SQLITE_DONE) {
        std::cerr << "Failed to insert record: " << sqlite3_errmsg(db_) << std::endl;
        return -1;
    }

    return static_cast<int>(sqlite3_last_insert_rowid(db_));
}

std::vector<ExperimentRecord> ResultsStorage::load_all() {
    std::vector<ExperimentRecord> results;
    if (!db_) return results;

    const char* select_sql = "SELECT * FROM experiments ORDER BY id;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return results;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ExperimentRecord rec;
        rec.id = sqlite3_column_int(stmt, 0);
        rec.timestamp = col_text(stmt, 1);
        rec.archive_name = col_text(stmt, 2);
        rec.archive_path = col_text(stmt, 3);
        rec.archive_size_bytes = sqlite3_column_int64(stmt, 4);
        rec.protection_type = col_text(stmt, 5);
        rec.charset_name = col_text(stmt, 6);
        rec.charset_size = static_cast<size_t>(sqlite3_column_int64(stmt, 7));
        rec.password_length = static_cast<size_t>(sqlite3_column_int64(stmt, 8));
        rec.total_space_size = static_cast<uint64_t>(sqlite3_column_int64(stmt, 9));
        rec.num_threads = sqlite3_column_int(stmt, 10);
        rec.total_checks = static_cast<uint64_t>(sqlite3_column_int64(stmt, 11));
        rec.total_time_ms = sqlite3_column_double(stmt, 12);
        rec.checks_per_second = sqlite3_column_double(stmt, 13);
        rec.cpu_load_percent = sqlite3_column_double(stmt, 14);
        rec.memory_resident_bytes = static_cast<uint64_t>(sqlite3_column_int64(stmt, 15));
        rec.memory_virtual_bytes = static_cast<uint64_t>(sqlite3_column_int64(stmt, 16));
        rec.compiler_flags = col_text(stmt, 17);
        rec.cpu_model = col_text(stmt, 18);
        rec.password_found = sqlite3_column_int(stmt, 19) != 0;
        rec.found_password = col_text(stmt, 20);
        rec.execution_mode = col_text(stmt, 21);
        results.push_back(rec);
    }

    sqlite3_finalize(stmt);
    return results;
}

std::vector<ExperimentRecord> ResultsStorage::load_by_archive(
    const std::string& archive_name) {
    std::vector<ExperimentRecord> results;
    if (!db_) return results;

    const char* select_sql = "SELECT * FROM experiments WHERE archive_name = ? ORDER BY id;";
    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, select_sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) return results;

    sqlite3_bind_text(stmt, 1, archive_name.c_str(), -1, SQLITE_TRANSIENT);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ExperimentRecord rec;
        rec.id = sqlite3_column_int(stmt, 0);
        rec.timestamp = col_text(stmt, 1);
        rec.archive_name = col_text(stmt, 2);
        rec.archive_path = col_text(stmt, 3);
        rec.archive_size_bytes = sqlite3_column_int64(stmt, 4);
        rec.protection_type = col_text(stmt, 5);
        rec.charset_name = col_text(stmt, 6);
        rec.charset_size = static_cast<size_t>(sqlite3_column_int64(stmt, 7));
        rec.password_length = static_cast<size_t>(sqlite3_column_int64(stmt, 8));
        rec.total_space_size = static_cast<uint64_t>(sqlite3_column_int64(stmt, 9));
        rec.num_threads = sqlite3_column_int(stmt, 10);
        rec.total_checks = static_cast<uint64_t>(sqlite3_column_int64(stmt, 11));
        rec.total_time_ms = sqlite3_column_double(stmt, 12);
        rec.checks_per_second = sqlite3_column_double(stmt, 13);
        rec.cpu_load_percent = sqlite3_column_double(stmt, 14);
        rec.memory_resident_bytes = static_cast<uint64_t>(sqlite3_column_int64(stmt, 15));
        rec.memory_virtual_bytes = static_cast<uint64_t>(sqlite3_column_int64(stmt, 16));
        rec.compiler_flags = col_text(stmt, 17);
        rec.cpu_model = col_text(stmt, 18);
        rec.password_found = sqlite3_column_int(stmt, 19) != 0;
        rec.found_password = col_text(stmt, 20);
        rec.execution_mode = col_text(stmt, 21);
        results.push_back(rec);
    }

    sqlite3_finalize(stmt);
    return results;
}

bool ResultsStorage::export_csv(const std::string& csv_path) {
    auto records = load_all();
    if (records.empty()) return false;

    std::ofstream csv(csv_path);
    if (!csv.is_open()) return false;

    csv << "id,timestamp,archive_name,archive_size_bytes,protection_type,"
        << "charset_name,charset_size,password_length,total_space_size,"
        << "num_threads,total_checks,total_time_ms,checks_per_second,"
        << "cpu_load_percent,memory_resident_bytes,memory_virtual_bytes,"
        << "compiler_flags,cpu_model,password_found,found_password,execution_mode\n";

    for (const auto& rec : records) {
        csv << rec.id << ","
            << rec.timestamp << ","
            << rec.archive_name << ","
            << rec.archive_size_bytes << ","
            << rec.protection_type << ","
            << rec.charset_name << ","
            << rec.charset_size << ","
            << rec.password_length << ","
            << rec.total_space_size << ","
            << rec.num_threads << ","
            << rec.total_checks << ","
            << rec.total_time_ms << ","
            << rec.checks_per_second << ","
            << rec.cpu_load_percent << ","
            << rec.memory_resident_bytes << ","
            << rec.memory_virtual_bytes << ","
            << rec.compiler_flags << ","
            << rec.cpu_model << ","
            << (rec.password_found ? 1 : 0) << ","
            << rec.found_password << ","
            << rec.execution_mode << "\n";
    }

    csv.close();
    return true;
}

ExperimentRecord ResultsStorage::build_record(
    const archive::ArchiveInfo& archive_info,
    const engine::BruteForceResult& engine_result,
    const stats::PerformanceMetrics& metrics,
    const std::string& compiler_flags,
    const std::string& cpu_model,
    const std::string& execution_mode) {

    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&t));

    ExperimentRecord record;
    record.id = -1;
    record.timestamp = time_buf;
    record.archive_name = archive_info.name;
    record.archive_path = archive_info.path;
    record.archive_size_bytes = archive_info.archive_size_bytes;
    record.protection_type = archive::encryption_type_name(archive_info.encryption);
    record.charset_name = metrics.charset_name;
    record.charset_size = metrics.charset_size;
    record.password_length = metrics.password_length;
    record.total_space_size = metrics.total_space_size;
    record.num_threads = metrics.num_threads;
    record.total_checks = metrics.total_checks;
    record.total_time_ms = metrics.total_elapsed_ms;
    record.checks_per_second = metrics.checks_per_second;
    record.cpu_load_percent = metrics.cpu_load_percent;
    record.memory_resident_bytes = metrics.peak_memory.resident_bytes;
    record.memory_virtual_bytes = metrics.peak_memory.virtual_bytes;
    record.compiler_flags = compiler_flags;
    record.cpu_model = cpu_model;
    record.password_found = engine_result.found;
    record.found_password = engine_result.password;
    record.execution_mode = execution_mode;

    return record;
}

} // namespace storage
