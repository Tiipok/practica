#include "gpu/gpu_checker.h"
#include "gpu/zipcrypto_util.h"
#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <zip.h>

namespace gpu {

namespace {

constexpr uint32_t kZipLocalHeaderSignature = 0x04034b50;
constexpr size_t kZipLocalHeaderSize = 30;
constexpr size_t kEncryptedDataSize = 16;
constexpr size_t kAesSaltSize = 16;
constexpr size_t kAesVerificationSize = 2;
constexpr size_t kMaxPasswordPackLength = 8;

constexpr uint8_t kZipCryptoExpectedCRC[4] = {0x0d, 0xca, 0x41, 0x0a};

uint16_t read_u16(const uint8_t* p) {
    return static_cast<uint16_t>(p[0])
        | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t read_u32(const uint8_t* p) {
    return static_cast<uint32_t>(p[0])
        | (static_cast<uint32_t>(p[1]) << 8)
        | (static_cast<uint32_t>(p[2]) << 16)
        | (static_cast<uint32_t>(p[3]) << 24);
}

} // namespace

GpuChecker::GpuChecker(const std::string& archive_path,
                       const std::string& known_password)
    : archive_path_(archive_path)
    , available_(false)
    , is_aes_(false)
{
    std::memset(encrypted_data_, 0, sizeof(encrypted_data_));
    std::memset(expected_bytes_, 0, sizeof(expected_bytes_));
    std::memset(aes_salt_, 0, sizeof(aes_salt_));
    std::memset(aes_enc_verify_, 0, sizeof(aes_enc_verify_));

    int error_code = 0;
    zip_t* archive = zip_open(archive_path_.c_str(), ZIP_RDONLY, &error_code);
    if (!archive) {
        std::cerr << "[GPU] Failed to open archive" << std::endl;
        return;
    }

    zip_stat_t stat;
    if (zip_stat_index(archive, 0, 0, &stat) < 0) {
        zip_close(archive);
        return;
    }

    if (!(stat.valid & ZIP_STAT_ENCRYPTION_METHOD)
        || stat.encryption_method == ZIP_EM_NONE) {
        std::cerr << "[GPU] Archive is not encrypted" << std::endl;
        zip_close(archive);
        return;
    }

    int enc_method = stat.encryption_method;
    zip_close(archive);

    if (enc_method == ZIP_EM_TRAD_PKWARE) {
        if (!kernel_.initialize("", "crack_zipcrypto")) return;
        if (!extract_zipcrypto_data()) return;
        if (!known_password.empty()) {
            compute_zipcrypto_expected_bytes(known_password, encrypted_data_, expected_bytes_);
        }
        is_aes_ = false;
    } else if (enc_method == ZIP_EM_AES_128
               || enc_method == ZIP_EM_AES_192
               || enc_method == ZIP_EM_AES_256) {
        if (!kernel_.initialize_device()) return;
        if (!kernel_.initialize_aes()) return;
        if (!extract_aes_data()) return;
        is_aes_ = true;
    } else {
        std::cerr << "[GPU] Unsupported encryption: " << enc_method << std::endl;
        return;
    }

    available_ = true;
}

GpuChecker::~GpuChecker() = default;

bool GpuChecker::is_available() const { return available_; }
bool GpuChecker::is_aes() const { return is_aes_; }

void GpuChecker::set_expected_bytes(const uint8_t bytes[4]) {
    expected_bytes_[0] = bytes[0];
    expected_bytes_[1] = bytes[1];
    expected_bytes_[2] = bytes[2];
    expected_bytes_[3] = bytes[3];
}

bool GpuChecker::extract_zipcrypto_data() {
    std::ifstream file(archive_path_, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[GPU] Failed to open file" << std::endl;
        return false;
    }

    uint8_t header[kZipLocalHeaderSize];
    if (!file.read(reinterpret_cast<char*>(header), kZipLocalHeaderSize)) return false;

    if (read_u32(header) != kZipLocalHeaderSignature) return false;

    uint16_t name_len = read_u16(header + 26);
    uint16_t extra_len = read_u16(header + 28);
    file.seekg(static_cast<std::streamoff>(kZipLocalHeaderSize + name_len + extra_len),
               std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(encrypted_data_), kEncryptedDataSize)) return false;

    for (size_t i = 0; i < 4; ++i) {
        expected_bytes_[i] = kZipCryptoExpectedCRC[i];
    }
    return true;
}

bool GpuChecker::extract_aes_data() {
    std::ifstream file(archive_path_, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "[GPU] Failed to open file" << std::endl;
        return false;
    }

    uint8_t header[kZipLocalHeaderSize];
    if (!file.read(reinterpret_cast<char*>(header), kZipLocalHeaderSize)) return false;

    if (read_u32(header) != kZipLocalHeaderSignature) {
        std::cerr << "[GPU] Invalid ZIP signature" << std::endl;
        return false;
    }

    uint16_t name_len = read_u16(header + 26);
    uint16_t extra_len = read_u16(header + 28);
    file.seekg(static_cast<std::streamoff>(kZipLocalHeaderSize + name_len + extra_len),
               std::ios::beg);

    if (!file.read(reinterpret_cast<char*>(aes_salt_), kAesSaltSize)) {
        std::cerr << "[GPU] Failed to read AES salt" << std::endl;
        return false;
    }

    if (!file.read(reinterpret_cast<char*>(aes_enc_verify_), kAesVerificationSize)) {
        std::cerr << "[GPU] Failed to read AES verification" << std::endl;
        return false;
    }

    return true;
}

bool GpuChecker::check_batch(const std::vector<std::string>& passwords,
                              std::string& out_found_password) {
    if (!available_ || passwords.empty()) return false;

    std::vector<uint64_t> packed;
    std::vector<uint8_t> lengths;
    packed.reserve(passwords.size());
    lengths.reserve(passwords.size());

    for (const auto& pw : passwords) {
        packed.push_back(pack_password(pw));
        lengths.push_back(static_cast<uint8_t>(pw.length()));
    }

    uint32_t found_idx = 0;
    bool found;

    if (is_aes_) {
        found = kernel_.check_aes_passwords(packed, lengths,
                                            aes_salt_, aes_enc_verify_,
                                            found_idx);
    } else {
        found = kernel_.check_passwords(packed, lengths,
                                        encrypted_data_, expected_bytes_,
                                        found_idx);
    }

    if (found && found_idx < passwords.size()) {
        out_found_password = passwords[found_idx];
        return true;
    }

    return false;
}

uint64_t GpuChecker::pack_password(const std::string& password) const {
    uint64_t result = 0;
    size_t len = std::min(password.length(), kMaxPasswordPackLength);
    for (size_t i = 0; i < len; i++) {
        result |= (static_cast<uint64_t>(
            static_cast<uint8_t>(password[i])) << (i * 8));
    }
    return result;
}

} // namespace gpu
