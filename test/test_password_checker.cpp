#include "checker/password_checker.h"
#include "archive/archive_manager.h"
#include <fstream>
#include <gtest/gtest.h>

class PasswordCheckerTest : public ::testing::Test {
protected:
    void SetUp() override {
        src_path_ = "/tmp/test_src_checker.txt";
        zip_path_ = "/tmp/test_checker.zip";

        std::ofstream src(src_path_);
        src << "Test content for password checker.";
        src.close();

        archive::ArchiveManager::create_test_archive(
            zip_path_, "secret", src_path_, archive::EncryptionType::ZIP_CRYPTO);
    }

    void TearDown() override {
        std::remove(src_path_.c_str());
        std::remove(zip_path_.c_str());
    }

    std::string src_path_;
    std::string zip_path_;
};

TEST_F(PasswordCheckerTest, CorrectPasswordReturnsTrue) {
    checker::PasswordChecker pc(zip_path_);
    EXPECT_TRUE(pc.check("secret"));
}

TEST_F(PasswordCheckerTest, WrongPasswordReturnsFalse) {
    checker::PasswordChecker pc(zip_path_);
    EXPECT_FALSE(pc.check("wrong"));
}

TEST_F(PasswordCheckerTest, EmptyPasswordReturnsFalse) {
    checker::PasswordChecker pc(zip_path_);
    EXPECT_FALSE(pc.check(""));
}

TEST_F(PasswordCheckerTest, ArchivePathAccessor) {
    checker::PasswordChecker pc(zip_path_);
    EXPECT_EQ(pc.archive_path(), zip_path_);
}
