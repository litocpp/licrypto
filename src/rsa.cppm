module;
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <rstd/macro.hpp>

export module licrypto:rsa;
import rstd;
export import :error;

using namespace rstd::prelude;
using namespace rstd::literals;

export namespace licrypto {

class RsaPublicKey {
  void *key_ = nullptr;
  explicit RsaPublicKey(void *key) : key_(key) {}

public:
  RsaPublicKey(const RsaPublicKey &) = delete;
  auto operator=(const RsaPublicKey &) -> RsaPublicKey & = delete;
  RsaPublicKey(RsaPublicKey &&other) noexcept
      : key_(rstd::exchange(other.key_, nullptr)) {}
  auto operator=(RsaPublicKey &&other) noexcept -> RsaPublicKey & {
    if (this != &other) {
      EVP_PKEY_free(static_cast<EVP_PKEY *>(key_));
      key_ = rstd::exchange(other.key_, nullptr);
    }
    return *this;
  }
  ~RsaPublicKey() { EVP_PKEY_free(static_cast<EVP_PKEY *>(key_)); }

  static auto from_pem(slice<u8> pem) -> CryptoResult<RsaPublicKey> {
    auto *bio = BIO_new_mem_buf(pem.as_raw_ptr(),
                                static_cast<int>(pem.len().to_primitive()));
    if (bio == nullptr)
      return Err(Error::Configuration(String::make("cannot read RSA key"_str)));
    auto *key = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (key == nullptr)
      return Err(
          Error::Configuration(String::make("invalid RSA public key"_str)));
    return Ok(RsaPublicKey(key));
  }
  auto encrypt(slice<u8> data) -> CryptoResult<Vec<u8>> {
    auto *context = EVP_PKEY_CTX_new(static_cast<EVP_PKEY *>(key_), nullptr);
    if (context == nullptr)
      return Err(Error::Configuration(
          String::make("cannot allocate RSA context"_str)));
    auto cleanup = [&] { EVP_PKEY_CTX_free(context); };
    if (EVP_PKEY_encrypt_init(context) <= 0) {
      cleanup();
      return Err(
          Error::Configuration(String::make("cannot initialize RSA"_str)));
    }
    if (EVP_PKEY_CTX_set_rsa_padding(context, RSA_NO_PADDING) <= 0) {
      cleanup();
      return Err(Error::Configuration(
          String::make("cannot configure RSA padding"_str)));
    }
    size_t length = 0;
    if (EVP_PKEY_encrypt(
            context, nullptr, &length,
            reinterpret_cast<const unsigned char *>(data.as_raw_ptr()),
            data.len().to_primitive()) <= 0) {
      cleanup();
      return Err(
          Error::Configuration(String::make("RSA encryption failed"_str)));
    }
    auto out = Vec<u8>::make();
    for (usize index{}; index < usize(length); ++index)
      out.push(u8());
    if (EVP_PKEY_encrypt(
            context,
            reinterpret_cast<unsigned char *>(out.as_mut_slice().as_raw_ptr()),
            &length, reinterpret_cast<const unsigned char *>(data.as_raw_ptr()),
            data.len().to_primitive()) <= 0) {
      cleanup();
      return Err(
          Error::Configuration(String::make("RSA encryption failed"_str)));
    }
    cleanup();
    out.truncate(usize(static_cast<unsigned long long>(length)));
    return Ok(rstd::move(out));
  }
};

} // namespace licrypto
