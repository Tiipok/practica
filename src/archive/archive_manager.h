#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace archive {

enum class EncryptionType : uint8_t {
    NONE = 0,
    ZIP_CRYPTO,
    AES_128,
    AES_192,
    AES_256
};

inline const char* encryption_type_name(EncryptionType t) {
    switch (t) {
        case EncryptionType::NONE:       return "none";
        case EncryptionType::ZIP_CRYPTO: return "ZipCrypto";
        case EncryptionType::AES_128:    return "AES-128";
        case EncryptionType::AES_192:    return "AES-192";
        case EncryptionType::AES_256:    return "AES-256";
    }
    return "unknown";
}

struct ArchiveInfo {
    std::string name;
    std::string path;
    std::string password;
    size_t password_length;
    std::string charset_name;
    EncryptionType encryption;
    int64_t archive_size_bytes;
    int64_t original_size_bytes;
    std::string creation_date;
};

class ArchiveManager {
public:
    static bool create_test_archive(const std::string& archive_path,
                                     const std::string& password,
                                     const std::string& source_file_path,
                                     EncryptionType encryption);

    static bool verify_password(const std::string& archive_path,
                                 const std::string& password);

    static std::vector<ArchiveInfo> create_test_suite(
        const std::string& output_dir,
        const std::string& source_file_path);

    static std::vector<ArchiveInfo> create_benchmark_suite(
        const std::string& output_dir,
        const std::string& source_file_path,
        size_t max_password_length = 5,
        int seed = 0);
};

} // namespace archive
