#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace charset {

enum class Type : uint8_t {
    DIGITS = 0,
    LOWERCASE,
    ALPHANUM
};

inline constexpr const char* type_name(Type t) {
    switch (t) {
        case Type::DIGITS:    return "digits";
        case Type::LOWERCASE: return "lowercase";
        case Type::ALPHANUM:  return "alphanum";
    }
    return "unknown";
}

constexpr size_t kMaxPasswordLength = 5;

class Charset {
public:
    explicit Charset(const std::string& chars, Type type);

    static Charset digits();
    static Charset lowercase();
    static Charset alphanum();

    static Charset from_type(Type type);

    char at(size_t index) const;
    size_t index_of(char c) const;

    size_t size() const { return chars_.size(); }
    const std::string& characters() const { return chars_; }
    Type type() const { return type_; }

private:
    std::string chars_;
    Type type_;
};

} // namespace charset
