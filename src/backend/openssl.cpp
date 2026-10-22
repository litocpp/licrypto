module;
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
module licrypto;
import :backend.openssl;
import :backend.openssl.error;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;
namespace licrypto::backend {
OpenSslDigest::OpenSslDigest(OpenSslDigest &&other) noexcept
    : context_(rstd::exchange(other.context_, nullptr)),
      algorithm_(rstd::exchange(other.algorithm_, nullptr)) {}
auto OpenSslDigest::operator=(OpenSslDigest &&other) noexcept
    -> OpenSslDigest & {
  if (this != &other) {
    EVP_MD_CTX_free(static_cast<EVP_MD_CTX *>(context_));
    EVP_MD_free(static_cast<EVP_MD *>(algorithm_));
    context_ = rstd::exchange(other.context_, nullptr);
    algorithm_ = rstd::exchange(other.algorithm_, nullptr);
  }
  return *this;
}
OpenSslDigest::~OpenSslDigest() {
  EVP_MD_CTX_free(static_cast<EVP_MD_CTX *>(context_));
  EVP_MD_free(static_cast<EVP_MD *>(algorithm_));
}
auto OpenSslDigest::make(const char *name) -> CryptoResult<OpenSslDigest> {
  ERR_clear_error();
  auto *algorithm = EVP_MD_fetch(nullptr, name, nullptr);
  if (!algorithm)
    return Err(openssl_failure("EVP_MD_fetch"_str, true));
  auto *context = EVP_MD_CTX_new();
  if (!context) {
    auto error = openssl_failure("EVP_MD_CTX_new"_str);
    EVP_MD_free(algorithm);
    return Err(rstd::move(error));
  }
  if (EVP_DigestInit_ex2(context, algorithm, nullptr) != 1) {
    auto error = openssl_failure("EVP_DigestInit_ex2"_str);
    EVP_MD_CTX_free(context);
    EVP_MD_free(algorithm);
    return Err(rstd::move(error));
  }
  return Ok(OpenSslDigest(context, algorithm));
}
auto OpenSslDigest::update(slice<u8> input) -> CryptoResult<empty> {
  if (!context_)
    return Err(Error::InvalidState("digest update"_Str));
  ERR_clear_error();
  if (EVP_DigestUpdate(static_cast<EVP_MD_CTX *>(context_), input.as_raw_ptr(),
                       input.len().to_primitive()) != 1) {
    auto error = openssl_failure("EVP_DigestUpdate"_str);
    EVP_MD_CTX_free(
        static_cast<EVP_MD_CTX *>(rstd::exchange(context_, nullptr)));
    return Err(rstd::move(error));
  }
  return Ok(empty{});
}
auto OpenSslDigest::finish(void *output, usize length) -> CryptoResult<empty> {
  if (!context_)
    return Err(Error::InvalidState("digest finalize"_Str));
  auto *context = static_cast<EVP_MD_CTX *>(rstd::exchange(context_, nullptr));
  ERR_clear_error();
  unsigned count{};
  auto rc =
      EVP_DigestFinal_ex(context, static_cast<unsigned char *>(output), &count);
  auto error = rc == 1 && usize(count) == length
                   ? None<Error>()
                   : Some(openssl_failure("EVP_DigestFinal_ex"_str));
  EVP_MD_CTX_free(context);
  if (error)
    return Err(rstd::move(error).unwrap());
  return Ok(empty{});
}
OpenSslMac::OpenSslMac(OpenSslMac &&other) noexcept
    : context_(rstd::exchange(other.context_, nullptr)),
      algorithm_(rstd::exchange(other.algorithm_, nullptr)) {}
auto OpenSslMac::operator=(OpenSslMac &&other) noexcept -> OpenSslMac & {
  if (this != &other) {
    EVP_MAC_CTX_free(static_cast<EVP_MAC_CTX *>(context_));
    EVP_MAC_free(static_cast<EVP_MAC *>(algorithm_));
    context_ = rstd::exchange(other.context_, nullptr);
    algorithm_ = rstd::exchange(other.algorithm_, nullptr);
  }
  return *this;
}
OpenSslMac::~OpenSslMac() {
  EVP_MAC_CTX_free(static_cast<EVP_MAC_CTX *>(context_));
  EVP_MAC_free(static_cast<EVP_MAC *>(algorithm_));
}
auto OpenSslMac::make(slice<u8> key) -> CryptoResult<OpenSslMac> {
  ERR_clear_error();
  auto *algorithm = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  if (!algorithm)
    return Err(openssl_failure("EVP_MAC_fetch"_str, true));
  auto *context = EVP_MAC_CTX_new(algorithm);
  if (!context) {
    auto error = openssl_failure("EVP_MAC_CTX_new"_str);
    EVP_MAC_free(algorithm);
    return Err(rstd::move(error));
  }
  char digest[] = "SHA256";
  auto params = array<OSSL_PARAM, 2>{
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0),
      OSSL_PARAM_construct_end()};
  unsigned char empty_key{};
  const auto *data =
      key.is_empty()
          ? &empty_key
          : reinterpret_cast<const unsigned char *>(key.as_raw_ptr());
  if (EVP_MAC_init(context, data, key.len().to_primitive(),
                   params.as_slice().as_raw_ptr()) != 1) {
    auto error = openssl_failure("EVP_MAC_init"_str);
    EVP_MAC_CTX_free(context);
    EVP_MAC_free(algorithm);
    return Err(rstd::move(error));
  }
  return Ok(OpenSslMac(context, algorithm));
}
auto OpenSslMac::update(slice<u8> input) -> CryptoResult<empty> {
  if (!context_)
    return Err(Error::InvalidState("HMAC update"_Str));
  ERR_clear_error();
  if (EVP_MAC_update(
          static_cast<EVP_MAC_CTX *>(context_),
          reinterpret_cast<const unsigned char *>(input.as_raw_ptr()),
          input.len().to_primitive()) != 1) {
    auto error = openssl_failure("EVP_MAC_update"_str);
    EVP_MAC_CTX_free(
        static_cast<EVP_MAC_CTX *>(rstd::exchange(context_, nullptr)));
    return Err(rstd::move(error));
  }
  return Ok(empty{});
}
auto OpenSslMac::finalize() && -> CryptoResult<array<u8, 32>> {
  if (!context_)
    return Err(Error::InvalidState("HMAC finalize"_Str));
  auto *context = static_cast<EVP_MAC_CTX *>(rstd::exchange(context_, nullptr));
  array<u8, 32> output{};
  size_t count{};
  ERR_clear_error();
  auto rc = EVP_MAC_final(
      context,
      reinterpret_cast<unsigned char *>(output.as_mut_slice().as_raw_ptr()),
      &count, 32);
  auto error = rc == 1 && count == 32
                   ? None<Error>()
                   : Some(openssl_failure("EVP_MAC_final"_str));
  EVP_MAC_CTX_free(context);
  if (error)
    return Err(rstd::move(error).unwrap());
  return Ok(rstd::move(output));
}
} // namespace licrypto::backend
