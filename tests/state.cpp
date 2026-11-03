#include <rstd/test/gtest.hpp>
import licrypto;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;

TEST(CryptoState, IoErrorMovePreservesOwnedPayloadAndNativeCode) {
  auto copied = [] {
    auto original = licrypto::Error::Io(rstd::io::Error::with_source(
        rstd::io::ErrorKind{rstd::io::ErrorKind::TimedOut},
        Box<rstd::dyn<rstd::error::Error>>::make(
            licrypto::Error::Protocol("owned failure"_Str))));
    return original;
  }();
  auto source =
      rstd::dyn<rstd::error::Error>::from_ref(copied)->source().unwrap();
  auto io = rstd::error::downcast_ref<rstd::io::Error>(source);
  ASSERT_TRUE(io.is_some());
  EXPECT_EQ((*io)->kind(), rstd::io::ErrorKind{rstd::io::ErrorKind::TimedOut});
  auto payload =
      rstd::error::downcast_ref<licrypto::Error>((*io)->get_ref().unwrap());
  ASSERT_TRUE(payload.is_some());
  ASSERT_TRUE((*payload)->is_Protocol());
  EXPECT_EQ((*payload)->as_Protocol().message.as_str(), "owned failure"_str);
  EXPECT_TRUE(
      rstd::dyn<rstd::error::Error>::from_ref(**io)->source().is_none());
  EXPECT_EQ(rstd::format("{}", copied),
            "TLS protocol error: owned failure"_str);

  auto native = [] {
    auto original =
        licrypto::Error::Io(rstd::io::Error::from_raw_os_error(i32::MIN));
    return original;
  }();
  auto native_source =
      rstd::dyn<rstd::error::Error>::from_ref(native)->source().unwrap();
  auto native_io = rstd::error::downcast_ref<rstd::io::Error>(native_source);
  ASSERT_TRUE(native_io.is_some());
  EXPECT_EQ((*native_io)->raw_os_error().unwrap(), i32::MIN);
  EXPECT_TRUE((*native_io)->get_ref().is_none());
}

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
