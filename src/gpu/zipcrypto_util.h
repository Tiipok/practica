#pragma once

#include <cstdint>
#include <string>

namespace gpu {

void compute_zipcrypto_expected_bytes(const std::string& password,
                                       const uint8_t encrypted_data[16],
                                       uint8_t out_expected[4]);

} // namespace gpu
