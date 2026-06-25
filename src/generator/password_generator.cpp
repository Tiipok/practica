#include "generator/password_generator.h"
#include <stdexcept>

namespace generator {

PasswordGenerator::PasswordGenerator(const charset::Charset& charset,
                                     size_t min_length,
                                     size_t max_length)
    : charset_(charset)
    , min_length_(min_length)
    , max_length_(max_length)
    , current_(0)
    , range_end_(0)
{
    if (min_length == 0 || min_length > max_length) {
        throw std::invalid_argument("Invalid password length range");
    }
    total_space_ = 0;
    uint64_t base = charset_.size();
    uint64_t accum = base;
    for (size_t l = 1; l <= max_length_; ++l) {
        if (l >= min_length_) {
            uint64_t prev = total_space_;
            total_space_ += accum;
            if (total_space_ < prev) {
                throw std::overflow_error("Password space too large");
            }
        }
        uint64_t prev_accum = accum;
        accum *= base;
        if (accum / base != prev_accum && l < max_length_) {
            throw std::overflow_error("Password space too large");
        }
    }
    range_end_ = total_space_;
}

void PasswordGenerator::reset() {
    current_ = 0;
}

void PasswordGenerator::reset_to(uint64_t start_index) {
    current_ = start_index;
}

void PasswordGenerator::set_range(uint64_t start, uint64_t end) {
    current_ = start;
    range_end_ = (end > total_space_) ? total_space_ : end;
}

std::optional<std::string> PasswordGenerator::next() {
    if (current_ >= range_end_) {
        return std::nullopt;
    }
    return index_to_password(current_++);
}

std::string PasswordGenerator::index_to_password(uint64_t index) const {
    size_t len = find_length_for_index(index);
    uint64_t offset = index - count_up_to_length(len);
    size_t base = charset_.size();

    std::string result(len, charset_.at(0));
    for (size_t pos = 0; pos < len; ++pos) {
        size_t char_idx = offset % base;
        offset /= base;
        result[len - 1 - pos] = charset_.at(char_idx);
    }
    return result;
}

uint64_t PasswordGenerator::password_to_index(const std::string& password) const {
    size_t len = password.length();
    uint64_t index = count_up_to_length(len);
    size_t base = charset_.size();
    uint64_t offset = 0;
    uint64_t multiplier = 1;

    for (size_t pos = 0; pos < len; ++pos) {
        size_t char_idx = charset_.index_of(password[len - 1 - pos]);
        offset += char_idx * multiplier;
        multiplier *= base;
    }
    return index + offset;
}

uint64_t PasswordGenerator::count_up_to_length(size_t len) const {
    uint64_t total = 0;
    size_t base = charset_.size();
    uint64_t accum = 1;
    for (size_t i = 0; i < min_length_; ++i) {
        accum *= base;
    }
    for (size_t l = min_length_; l < len && l <= max_length_; ++l) {
        total += accum;
        accum *= base;
    }
    return total;
}

size_t PasswordGenerator::find_length_for_index(uint64_t index) const {
    size_t base = charset_.size();
    uint64_t accum = 1;
    for (size_t i = 0; i < min_length_; ++i) {
        accum *= base;
    }
    uint64_t cumulative = 0;
    for (size_t l = min_length_; l <= max_length_; ++l) {
        cumulative += accum;
        if (index < cumulative) {
            return l;
        }
        accum *= base;
    }
    return max_length_;
}

} // namespace generator
