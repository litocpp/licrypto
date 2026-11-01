#include <rstd/test/gtest.hpp>
import licrypto;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;

TEST(CryptoState, ConsumedStateCannotProduceAnotherDigest) {
  auto state = licrypto::Sha256::make().unwrap();
  ASSERT_TRUE(state.update("abc"_str.as_bytes()).is_ok());
  ASSERT_TRUE(rstd::move(state).finalize().is_ok());
  auto update = state.update("def"_str.as_bytes());
  ASSERT_TRUE(update.is_err());
  EXPECT_TRUE(update.unwrap_err().is_InvalidState());
  auto again = rstd::move(state).finalize();
  ASSERT_TRUE(again.is_err());
  EXPECT_TRUE(again.unwrap_err().is_InvalidState());
}
TEST(CryptoState, MoveTransfersTheComputation) {
  auto original = licrypto::Sha512::make().unwrap();
  ASSERT_TRUE(original.update("a"_str.as_bytes()).is_ok());
  auto state = rstd::move(original);
  EXPECT_TRUE(original.update("wrong"_str.as_bytes()).is_err());
  ASSERT_TRUE(state.update("bc"_str.as_bytes()).is_ok());
  auto digest = rstd::move(state).finalize_digest().unwrap();
  EXPECT_EQ(digest, licrypto::sha512_digest("abc"_str).unwrap());
}
TEST(CryptoState, Sha256MoveAssignmentTransfersTheComputation) {
  auto source = licrypto::Sha256::make().unwrap();
  auto target = licrypto::Sha256::make().unwrap();
  ASSERT_TRUE(source.update("a"_str.as_bytes()).is_ok());
  ASSERT_TRUE(target.update("discarded"_str.as_bytes()).is_ok());
  target = rstd::move(source);
  EXPECT_TRUE(source.update("wrong"_str.as_bytes()).is_err());
  EXPECT_TRUE(rstd::move(source).finalize_digest().is_err());
  auto *same = &target;
  target = rstd::move(*same);
  ASSERT_TRUE(target.update("bc"_str.as_bytes()).is_ok());
  EXPECT_EQ(rstd::move(target).finalize_digest().unwrap(),
            licrypto::sha256_digest("abc"_str).unwrap());
  source = licrypto::Sha256::make().unwrap();
  ASSERT_TRUE(source.update("replacement"_str.as_bytes()).is_ok());
  target = rstd::move(source);
  EXPECT_TRUE(source.update("wrong"_str.as_bytes()).is_err());
  EXPECT_EQ(rstd::move(target).finalize_digest().unwrap(),
            licrypto::sha256_digest("replacement"_str).unwrap());
}
TEST(CryptoState, EmptyHmacKeyAndMessage) {
  auto digest = licrypto::hmac_sha256(""_str.as_bytes(), ""_str.as_bytes());
  ASSERT_TRUE(digest.is_ok());
  EXPECT_EQ(
      digest->to_hex(),
      "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad"_str);
}
TEST(CryptoState, HmacCannotBeReusedAfterFinalization) {
  auto state = licrypto::HmacSha256::make("key"_str.as_bytes()).unwrap();
  ASSERT_TRUE(rstd::move(state).finalize().is_ok());
  EXPECT_TRUE(state.update("data"_str.as_bytes()).is_err());
  EXPECT_TRUE(rstd::move(state).verify(""_str.as_bytes()).is_err());
}
