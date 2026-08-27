#include <rstd/test/gtest.hpp>

import licrypto;
import rstd;

using namespace rstd::literals;

TEST(Sha512, MatchesPublishedVectors) {
  EXPECT_EQ(
      licrypto::sha512_hex(""_str).as_str(),
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"_str);
  EXPECT_EQ(
      licrypto::sha512_hex("abc"_str).as_str(),
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2"
      "192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"_str);
  EXPECT_EQ(
      licrypto::sha512_hex(
          "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"_str)
          .as_str(),
      "204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c3359"
      "6fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445"_str);
}

TEST(Sha512, IncrementalMatchesOneShot) {
  constexpr auto input =
      "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"_str;
  auto expected = licrypto::sha512_hex(input);

  rstd::usize chunk_sizes[]{rstd::usize(1), rstd::usize(7), rstd::usize(128)};
  for (auto chunk_size : chunk_sizes) {
    auto state = licrypto::Sha512::make();
    for (rstd::usize offset{}; offset < input.len(); offset += chunk_size) {
      auto remaining = input.len() - offset;
      auto count = remaining < chunk_size ? remaining : chunk_size;
      state.update(rstd::slice<rstd::u8>::from_raw_parts(
          input.as_bytes().as_raw_ptr() + offset.to_primitive(), count));
    }
    EXPECT_EQ(licrypto::sha512_hex(rstd::move(state).finalize()), expected);
  }
}

TEST(Sha512, IncrementalCoversPaddingBoundaries) {
  rstd::usize lengths[]{rstd::usize(),    rstd::usize(111), rstd::usize(112),
                        rstd::usize(127), rstd::usize(128), rstd::usize(129)};
  for (auto length : lengths) {
    auto input = rstd::vec::Vec<rstd::u8>::with_capacity(length);
    for (rstd::usize index{}; index < length; ++index)
      input.push(rstd::u8(index.to_primitive() & 0xffu));
    auto state = licrypto::Sha512::make();
    auto split = length / rstd::usize(2);
    state.update(rstd::slice<rstd::u8>::from_raw_parts(input.as_ptr(), split));
    state.update(rstd::slice<rstd::u8>::from_raw_parts(
        input.as_ptr() + split.to_primitive(), length - split));
    EXPECT_EQ(licrypto::sha512_hex(rstd::move(state).finalize()),
              licrypto::sha512_hex(input.as_slice()));
  }
}

TEST(Sha512Digest, ParsesAndFormatsCanonicalHex) {
  constexpr auto lower =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_str;
  constexpr auto upper =
      "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
      "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"_str;

  auto parsed = licrypto::Sha512Digest::parse_hex(upper);
  auto lower_parsed = licrypto::Sha512Digest::parse_hex(lower);
  auto trait_parsed = rstd::from_str<licrypto::Sha512Digest>(lower);
  ASSERT_TRUE(parsed.is_ok());
  ASSERT_TRUE(lower_parsed.is_ok());
  ASSERT_TRUE(trait_parsed.is_ok());
  EXPECT_EQ(parsed->to_hex(), lower);
  EXPECT_EQ(rstd::format("{}", *parsed), lower);
  EXPECT_EQ(*parsed, *lower_parsed);
  EXPECT_EQ(*parsed, *trait_parsed);
  EXPECT_TRUE(licrypto::Sha512Digest::parse_hex("abc"_str).is_err());
  EXPECT_TRUE(
      licrypto::Sha512Digest::parse_hex(
          "z123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
          "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"_str)
          .is_err());
}

TEST(Sha512Digest, SupportsOneShotAndIncrementalHashing) {
  auto one_shot = licrypto::sha512_digest("abc"_str);
  auto state = licrypto::Sha512::make();
  state.update("a"_str.as_bytes());
  state.update("bc"_str.as_bytes());
  auto incremental = rstd::move(state).finalize_digest();

  EXPECT_EQ(one_shot, incremental);
  EXPECT_EQ(
      one_shot.to_hex(),
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2"
      "192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"_str);

  auto clone = one_shot.clone();
  auto first = rstd::hash::DefaultHasher(rstd::u64(3), rstd::u64(5));
  auto second = rstd::hash::DefaultHasher(rstd::u64(3), rstd::u64(5));
  rstd::hash::hash_into(one_shot, first);
  rstd::hash::hash_into(clone, second);
  EXPECT_EQ(first.finish(), second.finish());
}
