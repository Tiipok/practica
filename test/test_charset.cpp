#include "generator/charset.h"
#include <gtest/gtest.h>

TEST(CharsetTest, DigitsSize) {
    auto ch = charset::Charset::digits();
    EXPECT_EQ(ch.size(), 10);
    EXPECT_EQ(ch.type(), charset::Type::DIGITS);
}

TEST(CharsetTest, LowercaseSize) {
    auto ch = charset::Charset::lowercase();
    EXPECT_EQ(ch.size(), 26);
    EXPECT_EQ(ch.type(), charset::Type::LOWERCASE);
}

TEST(CharsetTest, AlphanumSize) {
    auto ch = charset::Charset::alphanum();
    EXPECT_EQ(ch.size(), 36);
    EXPECT_EQ(ch.type(), charset::Type::ALPHANUM);
}

TEST(CharsetTest, FromType) {
    EXPECT_EQ(charset::Charset::from_type(charset::Type::DIGITS).size(), 10);
    EXPECT_EQ(charset::Charset::from_type(charset::Type::LOWERCASE).size(), 26);
    EXPECT_EQ(charset::Charset::from_type(charset::Type::ALPHANUM).size(), 36);
}

TEST(CharsetTest, AtAndIndexOf) {
    auto ch = charset::Charset::digits();
    EXPECT_EQ(ch.at(0), '0');
    EXPECT_EQ(ch.at(9), '9');
    EXPECT_EQ(ch.index_of('0'), 0);
    EXPECT_EQ(ch.index_of('9'), 9);
    EXPECT_THROW(ch.at(10), std::out_of_range);
    EXPECT_THROW(ch.index_of('a'), std::invalid_argument);
}

TEST(CharsetTest, TypeNames) {
    EXPECT_STREQ(charset::type_name(charset::Type::DIGITS), "digits");
    EXPECT_STREQ(charset::type_name(charset::Type::LOWERCASE), "lowercase");
    EXPECT_STREQ(charset::type_name(charset::Type::ALPHANUM), "alphanum");
}

TEST(CharsetTest, MaxPasswordLength) {
    EXPECT_EQ(charset::kMaxPasswordLength, 5);
}
