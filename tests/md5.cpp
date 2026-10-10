#include <rstd/test/gtest.hpp>
import licrypto;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;

TEST(Md5, PublishedVectorsAndIncremental) {
  struct Vector {
    ref<str> input;
    ref<str> digest;
  };
  const Vector vectors[]{
      {""_str, "d41d8cd98f00b204e9800998ecf8427e"_str},
      {"a"_str, "0cc175b9c0f1b6a831c399e269772661"_str},
      {"abc"_str, "900150983cd24fb0d6963f7d28e17f72"_str},
      {"message digest"_str, "f96b697d7cb7938d525a2f31aaf161d0"_str},
      {"abcdefghijklmnopqrstuvwxyz"_str,
       "c3fcd3d76192e4007dfb496cca67e13b"_str},
      {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"_str,
       "d174ab98d277d9f5a5611c2c9f419d9f"_str},
      {"12345678901234567890123456789012345678901234567890123456789012345678901234567890"_str,
       "57edf4a22be3c955ac49da2e2107b67a"_str}};
  for (const auto &vector : vectors) {
    EXPECT_EQ(licrypto::md5_hex(vector.input), vector.digest);
    auto bytes = vector.input.as_bytes();
    for (usize split{}; split <= bytes.len(); ++split) {
      auto state = licrypto::Md5::make();
      state.update(slice<u8>::from_raw_parts(bytes.as_raw_ptr(), split));
      state.update(slice<u8>::from_raw_parts(
          bytes.as_raw_ptr() + split.to_primitive(), bytes.len() - split));
      EXPECT_EQ(licrypto::md5_hex(rstd::move(state).finalize()), vector.digest);
    }
  }
}

TEST(Md5, BinaryAndPaddingBoundaries) {
  EXPECT_EQ(licrypto::md5_hex("a\0b"_str),
            "70350f6027bce3713f6b76473084309b"_str);
  struct Vector {
    usize length;
    ref<str> digest;
  };
  const Vector vectors[]{{usize(55), "6912ee65fff2d9f9ce2508cddf8bcda0"_str},
                         {usize(56), "51fdd1acda72405dfdfa03fcb85896d7"_str},
                         {usize(63), "48a6295221902e8e0938f773a7185e72"_str},
                         {usize(64), "b2d3f56bc197fd985d5965079b5e7148"_str},
                         {usize(65), "8bd7053801c768420faf816fadba971c"_str},
                         {usize(128), "37eff01866ba3f538421b30b7cbefcac"_str}};
  for (const auto &vector : vectors) {
    Vec<u8> bytes;
    for (usize i{}; i < vector.length; ++i)
      bytes.push(u8(i.to_primitive()));
    for (usize split{}; split <= bytes.len(); ++split) {
      auto state = licrypto::Md5::make();
      state.update(slice<u8>::from_raw_parts(bytes.as_ptr(), split));
      state.update(slice<u8>::from_raw_parts(
          bytes.as_ptr() + split.to_primitive(), bytes.len() - split));
      EXPECT_EQ(licrypto::md5_hex(rstd::move(state).finalize()), vector.digest);
    }
  }
}
