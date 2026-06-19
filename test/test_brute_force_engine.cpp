#include "engine/brute_force_engine.h"
#include "archive/archive_manager.h"
#include "generator/charset.h"
#include <fstream>
#include <gtest/gtest.h>

class BruteForceEngineTest : public ::testing::Test {
protected:
    void SetUp() override {
        src_path_ = "/tmp/test_src_brute.txt";
        zip_path_ = "/tmp/test_brute.zip";

        std::ofstream src(src_path_);
        src << "Brute force engine test content.";
        src.close();

        archive::ArchiveManager::create_test_archive(
            zip_path_, "4821", src_path_, archive::EncryptionType::ZIP_CRYPTO);
    }

    void TearDown() override {
        std::remove(src_path_.c_str());
        std::remove(zip_path_.c_str());
    }

    std::string src_path_;
    std::string zip_path_;
};

TEST_F(BruteForceEngineTest, SingleThreadFindsPassword) {
    auto ch = charset::Charset::digits();
    generator::PasswordGenerator gen(ch, 4, 4);

    engine::BruteForceEngine engine(zip_path_);
    auto result = engine.run(gen, 1);

    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.password, "4821");
    EXPECT_EQ(result.total_checks, 4822);
}

TEST_F(BruteForceEngineTest, MultiThreadFindsPassword) {
    auto ch = charset::Charset::digits();
    generator::PasswordGenerator gen(ch, 4, 4);

    engine::BruteForceEngine engine(zip_path_);
    auto result = engine.run(gen, 4);

    EXPECT_TRUE(result.found);
    EXPECT_EQ(result.password, "4821");
    EXPECT_GT(result.total_checks, 0);
}

TEST_F(BruteForceEngineTest, StatsAreReasonable) {
    auto ch = charset::Charset::digits();
    generator::PasswordGenerator gen(ch, 4, 4);

    engine::BruteForceEngine engine(zip_path_);
    auto result = engine.run(gen, 2);

    EXPECT_TRUE(result.found);
    EXPECT_GT(result.total_elapsed_ms, 0);
    EXPECT_GT(result.checks_per_second, 0);
    EXPECT_EQ(result.num_threads, 2);
    EXPECT_EQ(result.total_space_size, 10000);
    EXPECT_EQ(static_cast<int>(result.worker_stats.size()), 2);
}

TEST_F(BruteForceEngineTest, ExhaustiveScanNoMatch) {
    auto ch = charset::Charset::digits();
    generator::PasswordGenerator gen(ch, 3, 3);

    engine::BruteForceEngine engine(zip_path_);
    auto result = engine.run(gen, 1);

    EXPECT_FALSE(result.found);
    EXPECT_EQ(result.total_checks, 1000);
}
