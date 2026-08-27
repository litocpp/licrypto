module;
#include <rstd/enum.hpp>

export module licrypto:sha512;

import rstd;

using namespace rstd::prelude;
using ::alloc::string::String;

export namespace licrypto {

class Sha512DigestParseError {
  RSTD_ENUM(Sha512DigestParseError, (Length, (usize actual;)),
            (Character, (usize index;)))
};

class Sha512Digest : public DefaultInClass<Sha512Digest, Clone> {
  array<u8, 64> bytes_;

public:
  static auto from_bytes(array<u8, 64> bytes) noexcept -> Sha512Digest {
    auto result = Sha512Digest{};
    result.bytes_ = rstd::move(bytes);
    return result;
  }

  static auto parse_hex(ref<str> value)
      -> Result<Sha512Digest, Sha512DigestParseError> {
    if (value.len() != usize(128))
      return Err(Sha512DigestParseError::Length(value.len()));
    auto bytes = array<u8, 64>{};
    auto nibble = [](u8 value) -> Option<u8> {
      const auto byte = value.to_primitive();
      if (byte >= '0' && byte <= '9')
        return Some(u8(byte - '0'));
      if (byte >= 'a' && byte <= 'f')
        return Some(u8(byte - 'a' + 10));
      if (byte >= 'A' && byte <= 'F')
        return Some(u8(byte - 'A' + 10));
      return None();
    };
    for (usize index{}; index < usize(64); ++index) {
      auto high = nibble(value[index * usize(2)]);
      if (high.is_none())
        return Err(Sha512DigestParseError::Character(index * usize(2)));
      auto low = nibble(value[index * usize(2) + usize(1)]);
      if (low.is_none())
        return Err(
            Sha512DigestParseError::Character(index * usize(2) + usize(1)));
      bytes[index] = u8((high->to_primitive() << 4u) | low->to_primitive());
    }
    return Ok(from_bytes(rstd::move(bytes)));
  }

  auto as_bytes() const noexcept -> slice<u8> { return bytes_.as_slice(); }

  auto to_hex() const -> String {
    static constexpr char digits[] = "0123456789abcdef";
    auto result = String::make();
    result.reserve(usize(128));
    for (const auto value : bytes_) {
      const auto byte = value.to_primitive();
      result.push_ascii(digits[byte >> 4u]);
      result.push_ascii(digits[byte & 0x0fu]);
    }
    return result;
  }

  auto clone() const -> Sha512Digest { return from_bytes(bytes_); }

  friend auto operator==(const Sha512Digest &left,
                         const Sha512Digest &right) noexcept -> bool {
    for (usize index{}; index < usize(64); ++index) {
      if (left.bytes_[index] != right.bytes_[index])
        return false;
    }
    return true;
  }
};

constexpr auto rotate_right(uint64_t value, uint64_t count) noexcept
    -> uint64_t {
  return (value >> count) | (value << (64u - count));
}

constexpr uint64_t SHA512_CONSTANTS[] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full,
    0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull,
    0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull,
    0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull, 0x2de92c6f592b0275ull,
    0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full,
    0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffCull,
    0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull,
    0x92722c851482353bull, 0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull,
    0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull,
    0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull,
    0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull,
    0xc67178f2e372532bull, 0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull,
    0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull,
    0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull,
};

class Sha512 {
  uint64_t state_[8] = {
      0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull,
      0xa54ff53a5f1d36f1ull, 0x510e527fade682d1ull, 0x9b05688c2b3e6c1full,
      0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull,
  };
  uint8_t block_[128]{};
  uint64_t length_high_{};
  uint64_t length_low_{};
  uint32_t block_length_{};

  void transform() noexcept {
    uint64_t words[80]{};
    for (uint32_t index{}; index < 16u; ++index) {
      const auto position = index * 8u;
      words[index] = (static_cast<uint64_t>(block_[position]) << 56u) |
                     (static_cast<uint64_t>(block_[position + 1u]) << 48u) |
                     (static_cast<uint64_t>(block_[position + 2u]) << 40u) |
                     (static_cast<uint64_t>(block_[position + 3u]) << 32u) |
                     (static_cast<uint64_t>(block_[position + 4u]) << 24u) |
                     (static_cast<uint64_t>(block_[position + 5u]) << 16u) |
                     (static_cast<uint64_t>(block_[position + 6u]) << 8u) |
                     static_cast<uint64_t>(block_[position + 7u]);
    }
    for (uint32_t index = 16u; index < 80u; ++index) {
      const auto previous = words[index - 15u];
      const auto near = words[index - 2u];
      const auto first = rotate_right(previous, 1u) ^
                         rotate_right(previous, 8u) ^ (previous >> 7u);
      const auto second =
          rotate_right(near, 19u) ^ rotate_right(near, 61u) ^ (near >> 6u);
      words[index] = words[index - 16u] + first + words[index - 7u] + second;
    }

    auto a = state_[0];
    auto b = state_[1];
    auto c = state_[2];
    auto d = state_[3];
    auto e = state_[4];
    auto f = state_[5];
    auto g = state_[6];
    auto h = state_[7];
    for (uint32_t index{}; index < 80u; ++index) {
      const auto sigma_one =
          rotate_right(e, 14u) ^ rotate_right(e, 18u) ^ rotate_right(e, 41u);
      const auto choice = (e & f) ^ ((~e) & g);
      const auto first =
          h + sigma_one + choice + SHA512_CONSTANTS[index] + words[index];
      const auto sigma_zero =
          rotate_right(a, 28u) ^ rotate_right(a, 34u) ^ rotate_right(a, 39u);
      const auto majority = (a & b) ^ (a & c) ^ (b & c);
      const auto second = sigma_zero + majority;
      h = g;
      g = f;
      f = e;
      e = d + first;
      d = c;
      c = b;
      b = a;
      a = first + second;
    }
    state_[0] += a;
    state_[1] += b;
    state_[2] += c;
    state_[3] += d;
    state_[4] += e;
    state_[5] += f;
    state_[6] += g;
    state_[7] += h;
  }

public:
  static auto make() noexcept -> Sha512 { return {}; }

  void update(slice<u8> input) noexcept {
    const auto length = static_cast<uint64_t>(input.len().to_primitive());
    length_low_ += length;
    if (length_low_ < length)
      ++length_high_;
    for (uint64_t index{}; index < length; ++index) {
      block_[block_length_++] = input[usize(index)].to_primitive();
      if (block_length_ != 128u)
        continue;
      transform();
      block_length_ = 0u;
    }
  }

  auto finalize() && noexcept -> array<u8, 64> {
    const auto bit_length_high = (length_high_ << 3u) | (length_low_ >> 61u);
    const auto bit_length_low = length_low_ << 3u;
    block_[block_length_++] = 0x80u;
    if (block_length_ > 112u) {
      while (block_length_ < 128u)
        block_[block_length_++] = 0u;
      transform();
      block_length_ = 0u;
    }
    while (block_length_ < 112u)
      block_[block_length_++] = 0u;
    for (uint32_t index{}; index < 8u; ++index) {
      const auto shift = 56u - index * 8u;
      block_[112u + index] =
          static_cast<uint8_t>((bit_length_high >> shift) & 0xffu);
      block_[120u + index] =
          static_cast<uint8_t>((bit_length_low >> shift) & 0xffu);
    }
    transform();

    auto result = array<u8, 64>{};
    for (uint32_t index{}; index < 8u; ++index) {
      for (uint32_t byte_index{}; byte_index < 8u; ++byte_index) {
        const auto shift = 56u - byte_index * 8u;
        result[usize(index * 8u + byte_index)] =
            u8((state_[index] >> shift) & 0xffu);
      }
    }
    return result;
  }

  auto finalize_digest() && noexcept -> Sha512Digest {
    return Sha512Digest::from_bytes(rstd::move(*this).finalize());
  }
};

auto sha512(slice<u8> input) noexcept -> array<u8, 64> {
  auto state = Sha512::make();
  state.update(input);
  return rstd::move(state).finalize();
}

auto sha512_hex(array<u8, 64> digest) -> String {
  static constexpr char digits[] = "0123456789abcdef";
  auto result = String::make();
  result.reserve(usize(128));
  for (const auto value : digest) {
    const auto byte = value.get().to_primitive();
    result.push_ascii(digits[byte >> 4u]);
    result.push_ascii(digits[byte & 0x0fu]);
  }
  return result;
}

auto sha512_hex(slice<u8> input) -> String { return sha512_hex(sha512(input)); }

auto sha512_hex(ref<str> input) -> String {
  return sha512_hex(input.as_bytes());
}

auto sha512_digest(slice<u8> input) noexcept -> Sha512Digest {
  return Sha512Digest::from_bytes(sha512(input));
}

auto sha512_digest(ref<str> input) noexcept -> Sha512Digest {
  return sha512_digest(input.as_bytes());
}

} // namespace licrypto

export namespace rstd {

template <> struct Impl<str_::FromStr, licrypto::Sha512Digest> {
  using Err = licrypto::Sha512DigestParseError;

  static auto from_str(ref<str> value) -> Result<licrypto::Sha512Digest, Err> {
    return licrypto::Sha512Digest::parse_hex(value);
  }
};

template <> struct Impl<convert::TryFrom<ref<str>>, licrypto::Sha512Digest> {
  using Error = licrypto::Sha512DigestParseError;

  static auto try_from(ref<str> value)
      -> Result<licrypto::Sha512Digest, Error> {
    return rstd::from_str<licrypto::Sha512Digest>(value);
  }
};

template <>
struct Impl<fmt::Display, licrypto::Sha512Digest>
    : ImplBase<licrypto::Sha512Digest> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    static constexpr char digits[] = "0123456789abcdef";
    for (const auto value : this->self().as_bytes()) {
      const auto byte = value.to_primitive();
      if (!formatter.write_raw(&digits[byte >> 4u], 1) ||
          !formatter.write_raw(&digits[byte & 0x0fu], 1))
        return false;
    }
    return true;
  }
};

template <>
struct Impl<fmt::Debug, licrypto::Sha512Digest>
    : ImplBase<licrypto::Sha512Digest> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    return as<fmt::Display>(this->self()).fmt(formatter);
  }
};

template <>
struct Impl<fmt::Display, licrypto::Sha512DigestParseError>
    : ImplBase<licrypto::Sha512DigestParseError> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    const auto &error = this->self();
    if (error.is_Length()) {
      return formatter.write_fmt(fmt::Arguments::make(
          "SHA-512 digest must contain 128 hexadecimal characters; found {}",
          error.as_Length().actual));
    }
    return formatter.write_fmt(fmt::Arguments::make(
        "SHA-512 digest contains a non-hexadecimal character at byte {}",
        error.as_Character().index));
  }
};

template <>
struct Impl<fmt::Debug, licrypto::Sha512DigestParseError>
    : ImplBase<licrypto::Sha512DigestParseError> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    return as<fmt::Display>(this->self()).fmt(formatter);
  }
};

template <>
struct Impl<error::Error, licrypto::Sha512DigestParseError>
    : DefaultInImpl<error::Error, licrypto::Sha512DigestParseError> {};

template <>
struct Impl<hash::Hash, licrypto::Sha512Digest>
    : ImplBase<licrypto::Sha512Digest> {
  template <typename H>
    requires Impled<H, hash::Hasher>
  void hash(H &state) const noexcept {
    rstd::as<hash::Hasher>(state).write(this->self().as_bytes());
  }
};

} // namespace rstd
