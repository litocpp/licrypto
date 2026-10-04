export module licrypto:hmac_sha256;
import :sha256;
import rstd;

using namespace rstd::prelude;

export namespace licrypto {
class HmacSha256 {
  Sha256 inner_, outer_;
  explicit HmacSha256(slice<u8> key) {
    array<u8, 64> block{};
    if (key.len() > usize(64)) {
      auto digest = sha256(key);
      for (usize i{}; i < usize(32); ++i)
        block[i] = digest[i];
    } else {
      for (usize i{}; i < key.len(); ++i)
        block[i] = key[i];
    }
    for (usize i{}; i < usize(64); ++i)
      block[i] = block[i] ^ u8(0x36);
    inner_.update(block.as_slice());
    for (usize i{}; i < usize(64); ++i)
      block[i] = block[i] ^ u8(0x36 ^ 0x5c);
    outer_.update(block.as_slice());
  }

public:
  static auto make(slice<u8> key) -> HmacSha256 { return HmacSha256(key); }
  void update(slice<u8> input) { inner_.update(input); }
  auto finalize() && -> Sha256Digest {
    auto inner = rstd::move(inner_).finalize();
    outer_.update(inner.as_slice());
    return rstd::move(outer_).finalize_digest();
  }
  // Full-length tags only. The length is public; content comparisons never exit
  // early.
  auto verify(slice<u8> tag) && -> bool {
    auto digest = rstd::move(*this).finalize();
    if (tag.len() != usize(32))
      return false;
    volatile unsigned char difference = 0;
    for (usize i{}; i < usize(32); ++i)
      difference = difference | (digest.as_bytes()[i] ^ tag[i]).to_primitive();
    return difference == 0;
  }
};
auto hmac_sha256(slice<u8> key, slice<u8> input) -> Sha256Digest {
  auto state = HmacSha256::make(key);
  state.update(input);
  return rstd::move(state).finalize();
}
auto verify_hmac_sha256(slice<u8> key, slice<u8> input, slice<u8> tag) -> bool {
  auto state = HmacSha256::make(key);
  state.update(input);
  return rstd::move(state).verify(tag);
}
} // namespace licrypto
