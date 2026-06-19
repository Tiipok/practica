#include "archive/archive_manager.h"
#include <fstream>
#include <gtest/gtest.h>

class ArchiveManagerTest : public ::testing::Test {
protected:
    void SetUp() override {
        src_path_ = "/tmp/test_source_archive.txt";
        zip_path_ = "/tmp/test_archive.zip";

        std::ofstream src(src_path_);
        src << "ZIP bruteforce research test file content.";
        src.close();
    }

    void TearDown() override {
        std::remove(src_path_.c_str());
        std::remove(zip_path_.c_str());
    }

    std::string src_path_;
    std::string zip_path_;
};

TEST_F(ArchiveManagerTest, CreateZipCryptoArchive) {
    bool ok = archive::ArchiveManager::create_test_archive(
        zip_path_, "test123", src_path_, archive::EncryptionType::ZIP_CRYPTO);
    EXPECT_TRUE(ok);

    std::ifstream f(zip_path_, std::ios::binary | std::ios::ate);
    EXPECT_TRUE(f.is_open());
    EXPECT_GT(f.tellg(), 0);
}

TEST_F(ArchiveManagerTest, CreateAes256Archive) {
    bool ok = archive::ArchiveManager::create_test_archive(
        zip_path_, "test456", src_path_, archive::EncryptionType::AES_256);
    EXPECT_TRUE(ok);
}

TEST_F(ArchiveManagerTest, VerifyCorrectPassword) {
    archive::ArchiveManager::create_test_archive(
        zip_path_, "pass1", src_path_, archive::EncryptionType::ZIP_CRYPTO);

    EXPECT_TRUE(archive::ArchiveManager::verify_password(zip_path_, "pass1"));
}

TEST_F(ArchiveManagerTest, VerifyWrongPassword) {
    archive::ArchiveManager::create_test_archive(
        zip_path_, "correct", src_path_, archive::EncryptionType::ZIP_CRYPTO);

    EXPECT_FALSE(archive::ArchiveManager::verify_password(zip_path_, "wrong"));
}

TEST_F(ArchiveManagerTest, VerifyAesPassword) {
    archive::ArchiveManager::create_test_archive(
        zip_path_, "aespass", src_path_, archive::EncryptionType::AES_256);

    EXPECT_TRUE(archive::ArchiveManager::verify_password(zip_path_, "aespass"));
    EXPECT_FALSE(archive::ArchiveManager::verify_password(zip_path_, "badpass"));
}
