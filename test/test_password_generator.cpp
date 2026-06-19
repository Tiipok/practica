#include "generator/password_generator.h"
#include "generator/charset.h"
#include <gtest/gtest.h>

TEST(PasswordGeneratorTest, DigitsLength1) {
    auto ch = charset::Charset::digits();
    generator::PasswordGenerator gen(ch, 1, 1);
    EXPECT_EQ(gen.total_space(), 10);

    std::vector<std::string> passwords;
    while (auto pw = gen.next()) {
        passwords.push_back(*pw);
    }
    EXPECT_EQ(passwords.size(), 10);
    EXPECT_EQ(passwords[0], "0");
    EXPECT_EQ(passwords[9], "9");
}

TEST(PasswordGeneratorTest, DigitsLength2Range) {
    auto ch = charset::Charset::digits();
    generator::PasswordGenerator gen(ch, 2, 2);
    EXPECT_EQ(gen.total_space(), 100);

    gen.set_range(0, 10);
    std::vector<std::string> passwords;
    while (auto pw = gen.next()) {
        passwords.push_back(*pw);
    }
    EXPECT_EQ(passwords.size(), 10);
    EXPECT_EQ(passwords[0], "00");
    EXPECT_EQ(passwords[9], "09");
}

TEST(PasswordGeneratorTest, LowercaseLength3) {
    auto ch = charset::Charset::lowercase();
    generator::PasswordGenerator gen(ch, 1, 1);
    EXPECT_EQ(gen.total_space(), 26);
}

TEST(PasswordGeneratorTest, AlphanumLength2) {
    auto ch = charset::Charset::alphanum();
    generator::PasswordGenerator gen(ch, 2, 2);
    EXPECT_EQ(gen.total_space(), 36 * 36);
}

TEST(PasswordGeneratorTest, IndexConversionDigits) {
    auto ch = charset::Charset::digits();
    generator::PasswordGenerator gen(ch, 1, 4);

    EXPECT_EQ(gen.index_to_password(0), "0");
    EXPECT_EQ(gen.index_to_password(9), "9");
    EXPECT_EQ(gen.index_to_password(10), "00");
    EXPECT_EQ(gen.index_to_password(11), "01");

    EXPECT_EQ(gen.password_to_index("0"), 0);
    EXPECT_EQ(gen.password_to_index("9"), 9);
    EXPECT_EQ(gen.password_to_index("00"), 10);
    EXPECT_EQ(gen.password_to_index("01"), 11);
}

TEST(PasswordGeneratorTest, IndexConversionRanges) {
    auto ch = charset::Charset::lowercase();
    generator::PasswordGenerator gen(ch, 1, 3);

    uint64_t idx = gen.password_to_index("a");
    auto pw = gen.index_to_password(idx);
    EXPECT_EQ(pw, "a");

    idx = gen.password_to_index("z");
    pw = gen.index_to_password(idx);
    EXPECT_EQ(pw, "z");
}

TEST(PasswordGeneratorTest, ResetTo) {
    auto ch = charset::Charset::digits();
    generator::PasswordGenerator gen(ch, 2, 2);

    gen.reset_to(50);
    auto pw = gen.next();
    EXPECT_TRUE(pw.has_value());
    EXPECT_EQ(*pw, "50");
}

TEST(PasswordGeneratorTest, InvalidRange) {
    auto ch = charset::Charset::digits();
    EXPECT_THROW(generator::PasswordGenerator gen(ch, 0, 1), std::invalid_argument);
    EXPECT_THROW(generator::PasswordGenerator gen(ch, 3, 1), std::invalid_argument);
}
