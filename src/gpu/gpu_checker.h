#pragma once

#include "gpu/metal_kernel.h"
#include <cstdint>
#include <string>
#include <vector>

namespace gpu {

class GpuChecker {
public:
    GpuChecker(const std::string& archive_path,
               const std::string& known_password = "");

    void set_expected_bytes(const uint8_t bytes[4]);
    ~GpuChecker();

    GpuChecker(const GpuChecker&) = delete;
    GpuChecker& operator=(const GpuChecker&) = delete;

    bool is_available() const;
    bool is_aes() const;

    bool check_batch(const std::vector<std::string>& passwords,
                     std::string& out_found_password);

private:
    bool extract_zipcrypto_data();
    bool extract_aes_data();

    uint64_t pack_password(const std::string& password) const;

    std::string archive_path_;
    MetalKernel kernel_;
    bool available_;
    bool is_aes_;

    uint8_t encrypted_data_[16];
    uint8_t expected_bytes_[4];

    uint8_t aes_salt_[16];
    uint8_t aes_enc_verify_[2];
};

} // namespace gpu
