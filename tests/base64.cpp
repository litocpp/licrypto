#include <rstd/test/gtest.hpp>

import licrypto;
import rstd;

using namespace rstd::literals;

TEST(Base64, MatchesPublishedVectors) {
  EXPECT_EQ(licrypto::base64_encode(""_str), ""_str);
  EXPECT_EQ(licrypto::base64_encode("f"_str), "Zg=="_str);
  EXPECT_EQ(licrypto::base64_encode("fo"_str), "Zm8="_str);
  EXPECT_EQ(licrypto::base64_encode("foo"_str), "Zm9v"_str);
  EXPECT_EQ(licrypto::base64_encode("foob"_str), "Zm9vYg=="_str);
  EXPECT_EQ(licrypto::base64_encode("fooba"_str), "Zm9vYmE="_str);
  EXPECT_EQ(licrypto::base64_encode("foobar"_str), "Zm9vYmFy"_str);
}

TEST(Base64, DecodesPublishedVectors) {
  constexpr auto encoded = rstd::array<rstd::ref<rstd::str>, 7>{
      ""_str,         "Zg=="_str,     "Zm8="_str,    "Zm9v"_str,
      "Zm9vYg=="_str, "Zm9vYmE="_str, "Zm9vYmFy"_str};
  constexpr auto decoded = rstd::array<rstd::ref<rstd::str>, 7>{
      ""_str,     "f"_str,     "fo"_str,    "foo"_str,
      "foob"_str, "fooba"_str, "foobar"_str};

  for (rstd::usize index{}; index < encoded.len(); ++index) {
    auto value = licrypto::base64_decode(encoded[index]);
    ASSERT_TRUE(value.is_ok());
    EXPECT_EQ(value->as_slice(), decoded[index].as_bytes());
  }
}

TEST(Base64, RoundTripsBinaryData) {
  auto input = rstd::vec::Vec<rstd::u8>::with_capacity(rstd::usize(257));
  for (rstd::usize index{}; index < rstd::usize(257); ++index)
    input.push(rstd::u8(index.to_primitive() & 0xffu));

  auto encoded = licrypto::base64_encode(input.as_slice());
  auto decoded = licrypto::base64_decode(encoded.as_str());
  ASSERT_TRUE(decoded.is_ok());
  EXPECT_EQ(decoded->as_slice(), input.as_slice());
}

TEST(Base64, RejectsMalformedAndNonCanonicalInput) {
  auto length = licrypto::base64_decode("Zg="_str);
  auto character = licrypto::base64_decode("Zm?v"_str);
  auto leading_padding = licrypto::base64_decode("=m9v"_str);
  auto split_padding = licrypto::base64_decode("Zm=v"_str);
  auto early_padding = licrypto::base64_decode("Zg==AAAA"_str);
  auto one_byte_tail = licrypto::base64_decode("Zh=="_str);
  auto two_byte_tail = licrypto::base64_decode("Zm9="_str);

  ASSERT_TRUE(length.is_err());
  ASSERT_TRUE(character.is_err());
  ASSERT_TRUE(leading_padding.is_err());
  ASSERT_TRUE(split_padding.is_err());
  ASSERT_TRUE(early_padding.is_err());
  ASSERT_TRUE(one_byte_tail.is_err());
  ASSERT_TRUE(two_byte_tail.is_err());
  EXPECT_TRUE(rstd::move(length).unwrap_err().is_Length());
  EXPECT_TRUE(rstd::move(character).unwrap_err().is_Character());
  EXPECT_TRUE(rstd::move(leading_padding).unwrap_err().is_Padding());
  EXPECT_TRUE(rstd::move(split_padding).unwrap_err().is_Padding());
  EXPECT_TRUE(rstd::move(early_padding).unwrap_err().is_Padding());
  EXPECT_TRUE(rstd::move(one_byte_tail).unwrap_err().is_TrailingBits());
  EXPECT_TRUE(rstd::move(two_byte_tail).unwrap_err().is_TrailingBits());
}
