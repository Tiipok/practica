#include "checker/password_checker.h"
#include <zip.h>
#include <utility>

namespace checker {

namespace {
constexpr int kReadBufferSize = 4096;
} // namespace

PasswordChecker::PasswordChecker(const std::string& archive_path)
    : archive_path_(archive_path) {}

PasswordChecker::~PasswordChecker() = default;

PasswordChecker::PasswordChecker(PasswordChecker&& other) noexcept
    : archive_path_(std::move(other.archive_path_)) {}

PasswordChecker& PasswordChecker::operator=(PasswordChecker&& other) noexcept {
    if (this != &other) {
        archive_path_ = std::move(other.archive_path_);
    }
    return *this;
}

bool PasswordChecker::check(const std::string& password) {
    int error_code = 0;
    zip_t* archive = zip_open(archive_path_.c_str(), ZIP_RDONLY, &error_code);
    if (!archive) {
        return false;
    }

    zip_int64_t num_entries = zip_get_num_entries(archive, 0);
    if (num_entries <= 0) {
        zip_close(archive);
        return false;
    }

    const char* entry_name = zip_get_name(archive, 0, 0);
    if (!entry_name) {
        zip_close(archive);
        return false;
    }

    const char* pwd = password.c_str();
    zip_file_t* file = zip_fopen_encrypted(archive, entry_name, 0, pwd);
    if (!file) {
        zip_close(archive);
        return false;
    }

    char buf[kReadBufferSize];
    zip_int64_t total = 0;
    zip_int64_t n;
    while ((n = zip_fread(file, buf, sizeof(buf))) > 0) {
        total += n;
    }
    zip_fclose(file);
    zip_close(archive);

    return total > 0 && n == 0;
}

} // namespace checker
