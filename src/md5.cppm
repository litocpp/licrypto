export module licrypto:md5;
import rstd;

using namespace rstd::prelude;
using rstd::string::String;

export namespace licrypto {

// MD5 is for legacy protocol compatibility, not collision-resistant security.
class Md5 {
  rstd::uint32_t state_[4]{0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u};
  rstd::uint8_t block_[64]{};
  rstd::uint64_t length_{};
  unsigned used_{};

  void transform() noexcept {
    static constexpr rstd::uint32_t constants[64]{
        0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu, 0xf57c0fafu,
        0x4787c62au, 0xa8304613u, 0xfd469501u, 0x698098d8u, 0x8b44f7afu,
        0xffff5bb1u, 0x895cd7beu, 0x6b901122u, 0xfd987193u, 0xa679438eu,
        0x49b40821u, 0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
        0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u, 0x21e1cde6u,
        0xc33707d6u, 0xf4d50d87u, 0x455a14edu, 0xa9e3e905u, 0xfcefa3f8u,
        0x676f02d9u, 0x8d2a4c8au, 0xfffa3942u, 0x8771f681u, 0x6d9d6122u,
        0xfde5380cu, 0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
        0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u, 0xd9d4d039u,
        0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u, 0xf4292244u, 0x432aff97u,
        0xab9423a7u, 0xfc93a039u, 0x655b59c3u, 0x8f0ccc92u, 0xffeff47du,
        0x85845dd1u, 0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
        0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u};
    static constexpr unsigned shifts[4][4]{
        {7, 12, 17, 22}, {5, 9, 14, 20}, {4, 11, 16, 23}, {6, 10, 15, 21}};
    rstd::uint32_t words[16]{};
    for (unsigned i{}; i < 16; ++i)
      for (unsigned j{}; j < 4; ++j)
        words[i] |= rstd::uint32_t(block_[i * 4 + j]) << (j * 8);
    auto a = state_[0], b = state_[1], c = state_[2], d = state_[3];
    for (unsigned i{}; i < 64; ++i) {
      rstd::uint32_t function;
      unsigned index;
      if (i < 16) {
        function = (b & c) | (~b & d);
        index = i;
      } else if (i < 32) {
        function = (d & b) | (~d & c);
        index = (5 * i + 1) % 16;
      } else if (i < 48) {
        function = b ^ c ^ d;
        index = (3 * i + 5) % 16;
      } else {
        function = c ^ (b | ~d);
        index = (7 * i) % 16;
      }
      auto value = a + function + constants[i] + words[index];
      auto shift = shifts[i / 16][i % 4];
      a = d;
      d = c;
      c = b;
      b += (value << shift) | (value >> (32 - shift));
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
  }

public:
  static auto make() noexcept -> Md5 { return {}; }
  void update(slice<u8> bytes) noexcept {
    length_ += bytes.len().to_primitive();
    for (auto value : bytes) {
      block_[used_++] = value.to_primitive();
      if (used_ == 64) {
        transform();
        used_ = 0;
      }
    }
  }
  auto finalize() && noexcept -> array<u8, 16> {
    auto bits = length_ * 8;
    block_[used_++] = 0x80;
    if (used_ > 56) {
      while (used_ < 64)
        block_[used_++] = 0;
      transform();
      used_ = 0;
    }
    while (used_ < 56)
      block_[used_++] = 0;
    for (unsigned i{}; i < 8; ++i)
      block_[56 + i] = static_cast<rstd::uint8_t>(bits >> (i * 8));
    transform();
    array<u8, 16> digest{};
    for (unsigned i{}; i < 4; ++i)
      for (unsigned j{}; j < 4; ++j)
        digest[usize(i * 4 + j)] = u8((state_[i] >> (j * 8)) & 255);
    return digest;
  }
};

auto md5(slice<u8> bytes) noexcept -> array<u8, 16> {
  auto state = Md5::make();
  state.update(bytes);
  return rstd::move(state).finalize();
}
auto md5_hex(array<u8, 16> digest) -> String {
  constexpr char digits[] = "0123456789abcdef";
  auto result = String::make();
  result.reserve(usize(32));
  for (auto value : digest) {
    auto byte = value.get().to_primitive();
    result.push(digits[byte >> 4]);
    result.push(digits[byte & 15]);
  }
  return result;
}
auto md5_hex(slice<u8> bytes) -> String { return md5_hex(md5(bytes)); }
auto md5_hex(ref<str> text) -> String { return md5_hex(text.as_bytes()); }

} // namespace licrypto
