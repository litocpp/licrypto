export module licrypto:sha1;

import rstd;

using namespace rstd::prelude;
using rstd::string::String;

export namespace licrypto {

// SHA-1 is retained for compatibility, not collision-resistant security.
class Sha1 {
  rstd::uint32_t state_[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu,
                              0x10325476u, 0xc3d2e1f0u};
  rstd::uint8_t block_[64]{};
  rstd::uint64_t length_{};
  rstd::uint32_t block_length_{};

  static constexpr auto rotate_left(rstd::uint32_t value,
                                    rstd::uint32_t count) noexcept
      -> rstd::uint32_t {
    return (value << count) | (value >> (32u - count));
  }

  void transform() noexcept {
    rstd::uint32_t words[80]{};
    for (rstd::uint32_t index{}; index < 16u; ++index) {
      const auto position = index * 4u;
      words[index] =
          (static_cast<rstd::uint32_t>(block_[position]) << 24u) |
          (static_cast<rstd::uint32_t>(block_[position + 1u]) << 16u) |
          (static_cast<rstd::uint32_t>(block_[position + 2u]) << 8u) |
          static_cast<rstd::uint32_t>(block_[position + 3u]);
    }
    for (rstd::uint32_t index = 16u; index < 80u; ++index)
      words[index] = rotate_left(words[index - 3u] ^ words[index - 8u] ^
                                     words[index - 14u] ^ words[index - 16u],
                                 1u);

    auto a = state_[0];
    auto b = state_[1];
    auto c = state_[2];
    auto d = state_[3];
    auto e = state_[4];
    for (rstd::uint32_t index{}; index < 80u; ++index) {
      rstd::uint32_t function;
      rstd::uint32_t constant;
      if (index < 20u) {
        function = (b & c) | (~b & d);
        constant = 0x5a827999u;
      } else if (index < 40u) {
        function = b ^ c ^ d;
        constant = 0x6ed9eba1u;
      } else if (index < 60u) {
        function = (b & c) | (b & d) | (c & d);
        constant = 0x8f1bbcdcu;
      } else {
        function = b ^ c ^ d;
        constant = 0xca62c1d6u;
      }
      const auto next =
          rotate_left(a, 5u) + function + e + constant + words[index];
      e = d;
      d = c;
      c = rotate_left(b, 30u);
      b = a;
      a = next;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
  }

public:
  static auto make() noexcept -> Sha1 { return {}; }

  void update(slice<u8> input) noexcept {
    length_ += static_cast<rstd::uint64_t>(input.len().to_primitive());
    for (const auto value : input) {
      block_[block_length_++] = value.to_primitive();
      if (block_length_ == 64u) {
        transform();
        block_length_ = 0u;
      }
    }
  }

  auto finalize() && noexcept -> array<u8, 20> {
    const auto bit_length = length_ * 8u;
    block_[block_length_++] = 0x80u;
    if (block_length_ > 56u) {
      while (block_length_ < 64u)
        block_[block_length_++] = 0u;
      transform();
      block_length_ = 0u;
    }
    while (block_length_ < 56u)
      block_[block_length_++] = 0u;
    for (rstd::uint32_t index{}; index < 8u; ++index)
      block_[56u + index] =
          static_cast<rstd::uint8_t>(bit_length >> (56u - index * 8u));
    transform();

    auto result = array<u8, 20>{};
    for (rstd::uint32_t index{}; index < 5u; ++index)
      for (rstd::uint32_t byte_index{}; byte_index < 4u; ++byte_index)
        result[usize(index * 4u + byte_index)] =
            u8((state_[index] >> (24u - byte_index * 8u)) & 0xffu);
    return result;
  }
};

auto sha1(slice<u8> input) noexcept -> array<u8, 20> {
  auto state = Sha1::make();
  state.update(input);
  return rstd::move(state).finalize();
}

auto sha1_hex(array<u8, 20> digest) -> String {
  static constexpr char digits[] = "0123456789abcdef";
  auto result = String::make();
  result.reserve(usize(40));
  for (const auto value : digest) {
    const auto byte = value.get().to_primitive();
    result.push_ascii(digits[byte >> 4u]);
    result.push_ascii(digits[byte & 0x0fu]);
  }
  return result;
}

auto sha1_hex(slice<u8> input) -> String { return sha1_hex(sha1(input)); }

auto sha1_hex(ref<str> input) -> String { return sha1_hex(input.as_bytes()); }

} // namespace licrypto
