#include <rstd/test/gtest.hpp>

import licrypto;
import rstd;

using namespace rstd::prelude;
using namespace rstd::literals;

TEST(Sha1, MatchesPublishedVectors) {
  EXPECT_EQ(licrypto::sha1_hex(""_str),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"_str);
  EXPECT_EQ(licrypto::sha1_hex("abc"_str),
            "a9993e364706816aba3e25717850c26c9cd0d89d"_str);
  EXPECT_EQ(licrypto::sha1_hex(
                "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"_str),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"_str);
  auto state = licrypto::Sha1::make();
  for (usize index{}; index < usize(1000000); ++index)
    state.update("a"_str.as_bytes());
  EXPECT_EQ(licrypto::sha1_hex(rstd::move(state).finalize()),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"_str);
}

TEST(Sha1, PreservesBinaryInput) {
  EXPECT_EQ(licrypto::sha1_hex("a\0b"_str),
            "4a3dec2d1f8245280855c42db0ee4239f917fdb8"_str);
  EXPECT_EQ(licrypto::sha1_hex("\xe4\xbd\xa0\xe5\xa5\xbd"_str),
            "440ee0853ad1e99f962b63e459ef992d7c211722"_str);
}

TEST(Sha1, IncrementalCoversPaddingBoundaries) {
  struct Vector {
    usize length;
    ref<str> digest;
  };
  const Vector vectors[] = {
      {usize(55), "8ae2d46729cfe68ff927af5eec9c7d1b66d65ac2"_str},
      {usize(56), "636e2ec698dac903498e648bd2f3af641d3c88cb"_str},
      {usize(63), "6d942da0c4392b123528f2905c713a3ce28364bd"_str},
      {usize(64), "c6138d514ffa2135bfce0ed0b8fac65669917ec7"_str},
      {usize(65), "69bd728ad6e13cd76ff19751fde427b00e395746"_str},
      {usize(128), "e6434bc401f98603d7eda504790c98c67385d535"_str},
  };
  for (const auto &vector : vectors) {
    auto input = rstd::vec::Vec<u8>::with_capacity(vector.length);
    for (usize index{}; index < vector.length; ++index)
      input.push(u8(index.to_primitive()));
    EXPECT_EQ(licrypto::sha1_hex(input.as_slice()), vector.digest);
    for (usize split{}; split <= vector.length; ++split) {
      auto state = licrypto::Sha1::make();
      state.update(slice<u8>::from_raw_parts(input.as_ptr(), split));
      state.update(""_str.as_bytes());
      state.update(slice<u8>::from_raw_parts(
          input.as_ptr() + split.to_primitive(), vector.length - split));
      EXPECT_EQ(licrypto::sha1_hex(rstd::move(state).finalize()),
                vector.digest);
    }
  }
}
