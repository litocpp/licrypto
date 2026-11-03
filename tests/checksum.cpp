#include <rstd/test/gtest.hpp>
import licrypto;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;

TEST(Checksum, KnownValues) {
  EXPECT_EQ(licrypto::crc32_ieee(""_bytes), u32(0));
  EXPECT_EQ(licrypto::adler32(""_bytes), u32(1));
  EXPECT_EQ(licrypto::crc32_ieee("123456789"_bytes), u32(0xcbf43926u));
  EXPECT_EQ(licrypto::adler32("123456789"_bytes), u32(0x091e01deu));
}

TEST(Checksum, SplitCopyAndReset) {
  auto crc = licrypto::Crc32Ieee::make();
  auto adler = licrypto::Adler32::make();
  crc.update("1234"_bytes);
  adler.update("1234"_bytes);
  auto crc_copy = crc;
  auto adler_copy = adler;
  crc_copy.update("56789"_bytes);
  adler_copy.update("56789"_bytes);
  EXPECT_EQ(crc_copy.value(), u32(0xcbf43926u));
  EXPECT_EQ(adler_copy.value(), u32(0x091e01deu));
  EXPECT_EQ(crc.value(), licrypto::crc32_ieee("1234"_bytes));
  EXPECT_EQ(adler.value(), licrypto::adler32("1234"_bytes));
  crc.reset();
  adler.reset();
  EXPECT_EQ(crc.value(), u32(0));
  EXPECT_EQ(adler.value(), u32(1));
  array<u8, 12000> bytes;
  for (auto byte : bytes)
    byte = u8(255);
  adler.update(bytes.as_slice());
  EXPECT_EQ(adler.value(), u32(0x09b1b3d3u));
}
