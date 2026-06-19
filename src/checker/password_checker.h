#pragma once

#include <string>

namespace checker {

class PasswordChecker {
public:
    explicit PasswordChecker(const std::string& archive_path);
    ~PasswordChecker();

    PasswordChecker(const PasswordChecker&) = delete;
    PasswordChecker& operator=(const PasswordChecker&) = delete;
    PasswordChecker(PasswordChecker&&) noexcept;
    PasswordChecker& operator=(PasswordChecker&&) noexcept;

    bool check(const std::string& password);

    const std::string& archive_path() const { return archive_path_; }

private:
    std::string archive_path_;
};

} // namespace checker
