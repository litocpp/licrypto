#include <rstd/test/gtest.hpp>
import licrypto;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;
using licrypto::HmacSha256;

template <rstd::size_t N> auto hmac_repeated(unsigned byte) -> array<u8, N> {
  array<u8, N> result{};
  for (usize i{}; i < usize(N); ++i)
    result[i] = u8(byte);
  return result;
}
TEST(HmacSha256, Rfc4231ShortAndBinaryKeys) {
  auto key = hmac_repeated<20>(0x0b);
  EXPECT_EQ(
      licrypto::hmac_sha256(key.as_slice(), "Hi There"_str.as_bytes())
          .to_hex()
          .as_str(),
      "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"_str);
  EXPECT_EQ(
      licrypto::hmac_sha256("Jefe"_str.as_bytes(),
                            "what do ya want for nothing?"_str.as_bytes())
          .to_hex()
          .as_str(),
      "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"_str);
  auto binary_key = hmac_repeated<20>(0xaa);
  auto data = hmac_repeated<50>(0xdd);
  EXPECT_EQ(
      licrypto::hmac_sha256(binary_key.as_slice(), data.as_slice())
          .to_hex()
          .as_str(),
      "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"_str);
}
TEST(HmacSha256, Rfc4231LongKeysAndStreaming) {
  auto key = hmac_repeated<131>(0xaa);
  EXPECT_EQ(
      licrypto::hmac_sha256(
          key.as_slice(),
          "Test Using Larger Than Block-Size Key - Hash Key First"_str
              .as_bytes())
          .to_hex()
          .as_str(),
      "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"_str);
  auto state = HmacSha256::make(key.as_slice());
  state.update(
      "This is a test using a larger than block-size key and a larger than block-size data. "_str
          .as_bytes());
  state.update(
      "The key needs to be hashed before being used by the HMAC algorithm."_str
          .as_bytes());
  EXPECT_EQ(
      rstd::move(state).finalize().to_hex().as_str(),
      "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"_str);
}
TEST(HmacSha256, VerificationRejectsEveryChangedByteAndWrongLength) {
  auto key = "test-key"_str.as_bytes();
  auto input = "test-message"_str.as_bytes();
  auto tag = licrypto::hmac_sha256(key, input);
  EXPECT_TRUE(licrypto::verify_hmac_sha256(key, input, tag.as_bytes()));
  for (usize i{}; i < usize(32); ++i) {
    array<u8, 32> changed{};
    for (usize n{}; n < usize(32); ++n)
      changed[n] = tag.as_bytes()[n];
    changed[i] = changed[i] ^ u8(1);
    EXPECT_FALSE(licrypto::verify_hmac_sha256(key, input, changed.as_slice()));
  }
  auto short_tag = hmac_repeated<16>(0);
  auto long_tag = hmac_repeated<33>(0);
  EXPECT_FALSE(licrypto::verify_hmac_sha256(key, input, short_tag.as_slice()));
  EXPECT_FALSE(licrypto::verify_hmac_sha256(key, input, long_tag.as_slice()));
  EXPECT_FALSE(licrypto::verify_hmac_sha256(key, "wrong"_str.as_bytes(),
                                            tag.as_bytes()));
}
