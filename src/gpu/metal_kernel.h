#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace gpu {

class MetalKernel {
public:
    MetalKernel();
    ~MetalKernel();

    MetalKernel(const MetalKernel&) = delete;
    MetalKernel& operator=(const MetalKernel&) = delete;

    bool initialize(const std::string& metallib_path_unused,
                    const std::string& kernel_name);

    bool initialize_device();
    bool initialize_aes();

    bool is_available() const;
    bool is_aes_available() const;

    bool check_passwords(
        const std::vector<uint64_t>& passwords_packed,
        const std::vector<uint8_t>& password_lengths,
        const uint8_t encrypted_data[16],
        const uint8_t expected_bytes[4],
        uint32_t& out_found_index);

    bool check_aes_passwords(
        const std::vector<uint64_t>& passwords_packed,
        const std::vector<uint8_t>& password_lengths,
        const uint8_t salt[16],
        const uint8_t encrypted_verification[2],
        uint32_t& out_found_index);

private:
    void* device_;
    void* command_queue_;
    void* pipeline_state_;
    void* aes_pipeline_state_;
    bool available_;
    bool aes_available_;
};

} // namespace gpu
