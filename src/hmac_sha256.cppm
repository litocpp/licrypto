module;
#include <rstd/macro.hpp>
export module licrypto:hmac_sha256;
export import :error;
import :sha256;
#if LITO_FEAT_OPENSSL
import :backend.openssl;
#endif
import rstd;
using namespace rstd::prelude;
export namespace licrypto {
class HmacSha256 {
#if LITO_FEAT_OPENSSL
  backend::OpenSslMac state_;
  explicit HmacSha256(backend::OpenSslMac state) : state_(rstd::move(state)) {}
#else
  Sha256 inner_, outer_;
  HmacSha256(Sha256 inner, Sha256 outer)
      : inner_(rstd::move(inner)), outer_(rstd::move(outer)) {}
#endif
public:
  HmacSha256(const HmacSha256 &) = delete;
  auto operator=(const HmacSha256 &) -> HmacSha256 & = delete;
  HmacSha256(HmacSha256 &&) noexcept = default;
  auto operator=(HmacSha256 &&) noexcept -> HmacSha256 & = default;
  static auto make(slice<u8> key) -> CryptoResult<HmacSha256> {
#if LITO_FEAT_OPENSSL
    return Ok(HmacSha256(rstd_try(backend::OpenSslMac::make(key))));
#else
    array<u8, 64> block{};
    if (key.len() > usize(64)) {
      auto digest = rstd_try(sha256(key));
      for (usize i{}; i < usize(32); ++i)
        block[i] = digest[i];
    } else {
      for (usize i{}; i < key.len(); ++i)
        block[i] = key[i];
    }
    auto inner = rstd_try(Sha256::make());
    auto outer = rstd_try(Sha256::make());
    for (usize i{}; i < usize(64); ++i)
      block[i] = block[i] ^ u8(0x36);
    rstd_try(inner.update(block.as_slice()));
    for (usize i{}; i < usize(64); ++i)
      block[i] = block[i] ^ u8(0x36 ^ 0x5c);
    rstd_try(outer.update(block.as_slice()));
    return Ok(HmacSha256(rstd::move(inner), rstd::move(outer)));
#endif
  }
  auto update(slice<u8> input) -> CryptoResult<empty> {
#if LITO_FEAT_OPENSSL
    return state_.update(input);
#else
    return inner_.update(input);
#endif
  }
  auto finalize() && -> CryptoResult<Sha256Digest> {
#if LITO_FEAT_OPENSSL
    return Ok(
        Sha256Digest::from_bytes(rstd_try(rstd::move(state_).finalize())));
#else
    auto digest = rstd_try(rstd::move(inner_).finalize());
    rstd_try(outer_.update(digest.as_slice()));
    return rstd::move(outer_).finalize_digest();
#endif
  }
  // Full-length tags only; the content comparison does not exit early.
  auto verify(slice<u8> tag) && -> CryptoResult<bool> {
    auto digest = rstd_try(rstd::move(*this).finalize());
    if (tag.len() != usize(32))
      return Ok(false);
    volatile unsigned char difference = 0;
    for (usize i{}; i < usize(32); ++i)
      difference = difference | (digest.as_bytes()[i] ^ tag[i]).to_primitive();
    return Ok(difference == 0);
  }
};
auto hmac_sha256(slice<u8> key, slice<u8> input) -> CryptoResult<Sha256Digest> {
  auto state = rstd_try(HmacSha256::make(key));
  rstd_try(state.update(input));
  return rstd::move(state).finalize();
}
auto verify_hmac_sha256(slice<u8> key, slice<u8> input, slice<u8> tag)
    -> CryptoResult<bool> {
  auto state = rstd_try(HmacSha256::make(key));
  rstd_try(state.update(input));
  return rstd::move(state).verify(tag);
}
} // namespace licrypto
