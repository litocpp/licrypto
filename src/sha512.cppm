module;
#include <rstd/enum.hpp>
#include <rstd/macro.hpp>

export module licrypto:sha512;

import rstd;
export import :error;
import :backend.digest;

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

class Sha512 {
  backend::DigestState<backend::Algorithm::Sha512, 64> state_;
  explicit Sha512(backend::DigestState<backend::Algorithm::Sha512, 64> state)
      : state_(rstd::move(state)) {}

public:
  Sha512(const Sha512 &) = delete;
  auto operator=(const Sha512 &) -> Sha512 & = delete;
  Sha512(Sha512 &&) noexcept = default;
  auto operator=(Sha512 &&) noexcept -> Sha512 & = default;
  static auto make() -> CryptoResult<Sha512> {
    auto state = rstd_try(
        (backend::DigestState<backend::Algorithm::Sha512, 64>::make()));
    return Ok(Sha512(rstd::move(state)));
  }
  auto update(slice<u8> input) -> CryptoResult<empty> {
    return state_.update(input);
  }
  auto finalize() && -> CryptoResult<array<u8, 64>> {
    return rstd::move(state_).finalize();
  }
  auto finalize_digest() && -> CryptoResult<Sha512Digest> {
    return Ok(Sha512Digest::from_bytes(rstd_try(rstd::move(*this).finalize())));
  }
};

auto sha512(slice<u8> input) -> CryptoResult<array<u8, 64>> {
  auto state = rstd_try(Sha512::make());
  rstd_try(state.update(input));
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

auto sha512_hex(slice<u8> input) -> CryptoResult<String> {
  return Ok(sha512_hex(rstd_try(sha512(input))));
}

auto sha512_hex(ref<str> input) -> CryptoResult<String> {
  return sha512_hex(input.as_bytes());
}

auto sha512_digest(slice<u8> input) -> CryptoResult<Sha512Digest> {
  return Ok(Sha512Digest::from_bytes(rstd_try(sha512(input))));
}

auto sha512_digest(ref<str> input) -> CryptoResult<Sha512Digest> {
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
