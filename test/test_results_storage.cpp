#include "storage/results_storage.h"
#include "archive/archive_manager.h"
#include "engine/brute_force_engine.h"
#include "stats/stats_collector.h"
#include <fstream>
#include <gtest/gtest.h>

class ResultsStorageTest : public ::testing::Test {
protected:
    void SetUp() override {
        db_path_ = "/tmp/test_experiments.db";
        std::remove(db_path_.c_str());
    }

    void TearDown() override {
        std::remove(db_path_.c_str());
    }

    std::string db_path_;
};

TEST_F(ResultsStorageTest, InitializeCreatesFile) {
    storage::ResultsStorage storage(db_path_);
    storage.initialize();

    std::ifstream f(db_path_, std::ios::binary);
    EXPECT_TRUE(f.is_open());
}

TEST_F(ResultsStorageTest, SaveAndLoadRecord) {
    storage::ResultsStorage storage(db_path_);
    storage.initialize();

    storage::ExperimentRecord rec;
    rec.timestamp = "2025-01-01 12:00:00";
    rec.archive_name = "test.zip";
    rec.archive_path = "/tmp/test.zip";
    rec.archive_size_bytes = 1024;
    rec.protection_type = "ZipCrypto";
    rec.charset_name = "digits";
    rec.charset_size = 10;
    rec.password_length = 4;
    rec.total_space_size = 10000;
    rec.num_threads = 4;
    rec.total_checks = 5000;
    rec.total_time_ms = 100.0;
    rec.checks_per_second = 50000.0;
    rec.cpu_load_percent = 75.0;
    rec.memory_resident_bytes = 1024 * 1024;
    rec.memory_virtual_bytes = 2 * 1024 * 1024;
    rec.compiler_flags = "Debug";
    rec.cpu_model = "Apple M4";
    rec.password_found = true;
    rec.found_password = "4821";

    int id = storage.save_result(rec);
    EXPECT_GT(id, 0);

    auto results = storage.load_all();
    EXPECT_EQ(results.size(), 1);
    EXPECT_EQ(results[0].archive_name, "test.zip");
    EXPECT_EQ(results[0].charset_name, "digits");
    EXPECT_EQ(results[0].password_length, 4);
    EXPECT_EQ(results[0].num_threads, 4);
    EXPECT_TRUE(results[0].password_found);
    EXPECT_EQ(results[0].found_password, "4821");
}

TEST_F(ResultsStorageTest, LoadByArchive) {
    storage::ResultsStorage storage(db_path_);
    storage.initialize();

    for (const auto& name : {"a.zip", "b.zip", "a.zip"}) {
        storage::ExperimentRecord rec;
        rec.archive_name = name;
        rec.timestamp = "2025-01-01";
        rec.protection_type = "ZipCrypto";
        rec.charset_name = "digits";
        rec.compiler_flags = "Debug";
        rec.cpu_model = "Apple M4";
        storage.save_result(rec);
    }

    auto results = storage.load_by_archive("a.zip");
    EXPECT_EQ(results.size(), 2);
}

TEST_F(ResultsStorageTest, BuildRecord) {
    storage::ResultsStorage storage(db_path_);
    storage.initialize();

    archive::ArchiveInfo arch_info;
    arch_info.name = "test.zip";
    arch_info.path = "/tmp/test.zip";
    arch_info.password = "1234";
    arch_info.password_length = 4;
    arch_info.charset_name = "digits";
    arch_info.encryption = archive::EncryptionType::ZIP_CRYPTO;
    arch_info.archive_size_bytes = 512;

    engine::BruteForceResult eng_result;
    eng_result.found = true;
    eng_result.password = "1234";
    eng_result.total_checks = 1235;
    eng_result.total_elapsed_ms = 50.0;
    eng_result.checks_per_second = 25000.0;
    eng_result.num_threads = 4;
    eng_result.total_space_size = 10000;

    stats::PerformanceMetrics metrics;
    metrics.num_threads = 4;
    metrics.total_checks = 1235;
    metrics.total_elapsed_ms = 50.0;
    metrics.checks_per_second = 25000.0;
    metrics.password_length = 4;
    metrics.charset_name = "digits";
    metrics.charset_size = 10;
    metrics.total_space_size = 10000;
    metrics.cpu_load_percent = 80.0;

    auto rec = storage.build_record(arch_info, eng_result, metrics, "Debug", "Apple M4");
    EXPECT_EQ(rec.archive_name, "test.zip");
    EXPECT_TRUE(rec.password_found);
    EXPECT_EQ(rec.found_password, "1234");
}
