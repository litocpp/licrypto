module;
#include <openssl/evp.h>
#include <rstd/macro.hpp>

export module licrypto:cipher;
import rstd;
export import :error;

using namespace rstd::prelude;
using namespace rstd::literals;

export namespace licrypto {

enum class AesMode { Cbc, Ecb };

class CipherContext {
  void *context_ = nullptr;
  explicit CipherContext(void *context) : context_(context) {}

public:
  CipherContext(const CipherContext &) = delete;
  auto operator=(const CipherContext &) -> CipherContext & = delete;
  CipherContext(CipherContext &&other) noexcept
      : context_(rstd::exchange(other.context_, nullptr)) {}
  auto operator=(CipherContext &&other) noexcept -> CipherContext & {
    if (this != &other) {
      EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(context_));
      context_ = rstd::exchange(other.context_, nullptr);
    }
    return *this;
  }
  ~CipherContext() {
    EVP_CIPHER_CTX_free(static_cast<EVP_CIPHER_CTX *>(context_));
  }

  static auto make() -> CryptoResult<CipherContext> {
    auto *context = EVP_CIPHER_CTX_new();
    if (context == nullptr)
      return Err(Error::Configuration(
          String::make("cannot allocate cipher context"_str)));
    return Ok(CipherContext(context));
  }
  auto get() const noexcept -> EVP_CIPHER_CTX * {
    return static_cast<EVP_CIPHER_CTX *>(context_);
  }
};

inline auto aes_cipher(AesMode mode) -> const EVP_CIPHER * {
  return mode == AesMode::Cbc ? EVP_aes_128_cbc() : EVP_aes_128_ecb();
}

inline auto aes_encrypt(AesMode mode, slice<u8> key, slice<u8> iv,
                        slice<u8> data) -> CryptoResult<Vec<u8>> {
  if (key.len() != usize(16))
    return Err(
        Error::Configuration(String::make("AES key must be 16 bytes"_str)));
  if (mode == AesMode::Cbc && iv.len() != usize(16))
    return Err(
        Error::Configuration(String::make("AES IV must be 16 bytes"_str)));
  auto context = CipherContext::make();
  if (context.is_err())
    return Err(rstd::move(context).unwrap_err());
  auto &cipher = *context;
  if (EVP_EncryptInit_ex(cipher.get(), aes_cipher(mode), nullptr, nullptr,
                         nullptr) != 1)
    return Err(Error::Configuration(
        String::make("cannot initialize AES encryption"_str)));
  if (EVP_CIPHER_CTX_set_padding(cipher.get(), 1) != 1)
    return Err(
        Error::Configuration(String::make("cannot configure AES padding"_str)));
  const unsigned char *iv_ptr =
      mode == AesMode::Cbc
          ? reinterpret_cast<const unsigned char *>(iv.as_raw_ptr())
          : nullptr;
  if (EVP_EncryptInit_ex(
          cipher.get(), nullptr, nullptr,
          reinterpret_cast<const unsigned char *>(key.as_raw_ptr()),
          iv_ptr) != 1)
    return Err(Error::Configuration(String::make("cannot set AES key"_str)));
  auto out = Vec<u8>::make();
  for (usize index{}; index < data.len() + usize(16); ++index)
    out.push(u8());
  int written = 0;
  auto *output =
      reinterpret_cast<unsigned char *>(out.as_mut_slice().as_raw_ptr());
  if (EVP_EncryptUpdate(
          cipher.get(), output, &written,
          reinterpret_cast<const unsigned char *>(data.as_raw_ptr()),
          static_cast<int>(data.len().to_primitive())) != 1)
    return Err(Error::Configuration(String::make("AES encryption failed"_str)));
  int final_written = 0;
  if (EVP_EncryptFinal_ex(cipher.get(), output + written, &final_written) != 1)
    return Err(Error::Configuration(String::make("AES encryption failed"_str)));
  out.truncate(usize(static_cast<unsigned long long>(written + final_written)));
  return Ok(rstd::move(out));
}

inline auto aes_decrypt(AesMode mode, slice<u8> key, slice<u8> iv,
                        slice<u8> data) -> CryptoResult<Vec<u8>> {
  if (key.len() != usize(16))
    return Err(
        Error::Configuration(String::make("AES key must be 16 bytes"_str)));
  if (mode == AesMode::Cbc && iv.len() != usize(16))
    return Err(
        Error::Configuration(String::make("AES IV must be 16 bytes"_str)));
  auto context = CipherContext::make();
  if (context.is_err())
    return Err(rstd::move(context).unwrap_err());
  auto &cipher = *context;
  if (EVP_DecryptInit_ex(cipher.get(), aes_cipher(mode), nullptr, nullptr,
                         nullptr) != 1)
    return Err(Error::Configuration(
        String::make("cannot initialize AES decryption"_str)));
  if (EVP_CIPHER_CTX_set_padding(cipher.get(), 1) != 1)
    return Err(
        Error::Configuration(String::make("cannot configure AES padding"_str)));
  const unsigned char *iv_ptr =
      mode == AesMode::Cbc
          ? reinterpret_cast<const unsigned char *>(iv.as_raw_ptr())
          : nullptr;
  if (EVP_DecryptInit_ex(
          cipher.get(), nullptr, nullptr,
          reinterpret_cast<const unsigned char *>(key.as_raw_ptr()),
          iv_ptr) != 1)
    return Err(Error::Configuration(String::make("cannot set AES key"_str)));
  auto out = Vec<u8>::make();
  for (usize index{}; index < data.len() + usize(16); ++index)
    out.push(u8());
  int written = 0;
  auto *output =
      reinterpret_cast<unsigned char *>(out.as_mut_slice().as_raw_ptr());
  if (EVP_DecryptUpdate(
          cipher.get(), output, &written,
          reinterpret_cast<const unsigned char *>(data.as_raw_ptr()),
          static_cast<int>(data.len().to_primitive())) != 1)
    return Err(Error::Configuration(String::make("AES decryption failed"_str)));
  int final_written = 0;
  if (EVP_DecryptFinal_ex(cipher.get(), output + written, &final_written) != 1)
    return Err(Error::Configuration(String::make("AES decryption failed"_str)));
  out.truncate(usize(static_cast<unsigned long long>(written + final_written)));
  return Ok(rstd::move(out));
}

} // namespace licrypto
