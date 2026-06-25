#pragma once

#include "charset.h"
#include <cstdint>
#include <optional>
#include <string>

namespace generator {

class PasswordGenerator {
public:
    PasswordGenerator(const charset::Charset& charset,
                      size_t min_length,
                      size_t max_length);

    void reset();
    void reset_to(uint64_t start_index);

    std::optional<std::string> next();

    void set_range(uint64_t start, uint64_t end);

    std::string index_to_password(uint64_t index) const;
    uint64_t password_to_index(const std::string& password) const;

    size_t min_length() const { return min_length_; }
    size_t max_length() const { return max_length_; }
    uint64_t total_space() const { return total_space_; }
    const charset::Charset& charset() const { return charset_; }

    uint64_t current_index() const { return current_; }

private:
    uint64_t count_up_to_length(size_t len) const;
    size_t find_length_for_index(uint64_t index) const;

    charset::Charset charset_;
    size_t min_length_;
    size_t max_length_;
    uint64_t total_space_;
    uint64_t current_;
    uint64_t range_end_;
};

} // namespace generator
