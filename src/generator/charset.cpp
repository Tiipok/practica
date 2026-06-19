#include "generator/charset.h"
#include <algorithm>
#include <stdexcept>

namespace charset {

Charset::Charset(const std::string& chars, Type type)
    : chars_(chars), type_(type) {}

Charset Charset::digits() {
    return Charset("0123456789", Type::DIGITS);
}

Charset Charset::lowercase() {
    return Charset("abcdefghijklmnopqrstuvwxyz", Type::LOWERCASE);
}

Charset Charset::alphanum() {
    return Charset(
        "abcdefghijklmnopqrstuvwxyz0123456789",
        Type::ALPHANUM);
}

Charset Charset::from_type(Type type) {
    switch (type) {
        case Type::DIGITS:    return digits();
        case Type::LOWERCASE: return lowercase();
        case Type::ALPHANUM:  return alphanum();
    }
    throw std::invalid_argument("Unknown charset type");
}

char Charset::at(size_t index) const {
    if (index >= chars_.size()) {
        throw std::out_of_range("Charset index out of range");
    }
    return chars_[index];
}

size_t Charset::index_of(char c) const {
    auto it = std::find(chars_.begin(), chars_.end(), c);
    if (it == chars_.end()) {
        throw std::invalid_argument(std::string("Character '") + c + "' not in charset");
    }
    return static_cast<size_t>(std::distance(chars_.begin(), it));
}

} // namespace charset
