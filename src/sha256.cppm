module;
#include <rstd/enum.hpp>
#include <rstd/macro.hpp>

export module licrypto:sha256;

import rstd;
export import :error;
import :backend.digest;

using namespace rstd::prelude;
using ::alloc::string::String;

export namespace licrypto {

class Sha256DigestParseError {
  RSTD_ENUM(Sha256DigestParseError, (Length, (usize actual;)),
            (Character, (usize index;)))
};

class Sha256Digest : public DefaultInClass<Sha256Digest, Clone> {
  array<u8, 32> bytes_;

public:
  static auto from_bytes(array<u8, 32> bytes) noexcept -> Sha256Digest {
    auto result = Sha256Digest{};
    result.bytes_ = rstd::move(bytes);
    return result;
  }

  static auto parse_hex(ref<str> value)
      -> Result<Sha256Digest, Sha256DigestParseError> {
    if (value.len() != usize(64))
      return Err(Sha256DigestParseError::Length(value.len()));
    auto bytes = array<u8, 32>{};
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
    for (usize index{}; index < usize(32); ++index) {
      auto high = nibble(value[index * usize(2)]);
      if (high.is_none())
        return Err(Sha256DigestParseError::Character(index * usize(2)));
      auto low = nibble(value[index * usize(2) + usize(1)]);
      if (low.is_none())
        return Err(
            Sha256DigestParseError::Character(index * usize(2) + usize(1)));
      bytes[index] = u8((high->to_primitive() << 4u) | low->to_primitive());
    }
    return Ok(from_bytes(rstd::move(bytes)));
  }

  auto as_bytes() const noexcept -> slice<u8> { return bytes_.as_slice(); }

  auto to_hex() const -> String {
    static constexpr char digits[] = "0123456789abcdef";
    auto result = String::make();
    result.reserve(usize(64));
    for (const auto value : bytes_) {
      const auto byte = value.to_primitive();
      result.push_ascii(digits[byte >> 4u]);
      result.push_ascii(digits[byte & 0x0fu]);
    }
    return result;
  }

  auto clone() const -> Sha256Digest { return from_bytes(bytes_); }

  friend auto operator==(const Sha256Digest &left,
                         const Sha256Digest &right) noexcept -> bool {
    for (usize index{}; index < usize(32); ++index) {
      if (left.bytes_[index] != right.bytes_[index])
        return false;
    }
    return true;
  }
};

class Sha256 {
  backend::DigestState<backend::Algorithm::Sha256, 32> state_;
  explicit Sha256(backend::DigestState<backend::Algorithm::Sha256, 32> state)
      : state_(rstd::move(state)) {}

public:
  Sha256(const Sha256 &) = delete;
  auto operator=(const Sha256 &) -> Sha256 & = delete;
  Sha256(Sha256 &&) noexcept = default;
  auto operator=(Sha256 &&other) noexcept -> Sha256 & {
    if (this != &other)
      state_ = rstd::move(other.state_);
    return *this;
  }
  static auto make() -> CryptoResult<Sha256> {
    auto state = rstd_try(
        (backend::DigestState<backend::Algorithm::Sha256, 32>::make()));
    return Ok(Sha256(rstd::move(state)));
  }
  auto update(slice<u8> input) -> CryptoResult<empty> {
    return state_.update(input);
  }
  auto finalize() && -> CryptoResult<array<u8, 32>> {
    return rstd::move(state_).finalize();
  }
  auto finalize_digest() && -> CryptoResult<Sha256Digest> {
    return Ok(Sha256Digest::from_bytes(rstd_try(rstd::move(*this).finalize())));
  }
};

auto sha256(slice<u8> input) -> CryptoResult<array<u8, 32>> {
  auto state = rstd_try(Sha256::make());
  rstd_try(state.update(input));
  return rstd::move(state).finalize();
}

auto sha256_hex(array<u8, 32> digest) -> String {
  static constexpr char digits[] = "0123456789abcdef";
  auto result = String::make();
  result.reserve(usize(64));
  for (const auto value : digest) {
    const auto byte = value.get().to_primitive();
    result.push_ascii(digits[byte >> 4u]);
    result.push_ascii(digits[byte & 0x0fu]);
  }
  return result;
}

auto sha256_hex(slice<u8> input) -> CryptoResult<String> {
  return Ok(sha256_hex(rstd_try(sha256(input))));
}

auto sha256_hex(ref<str> input) -> CryptoResult<String> {
  return sha256_hex(input.as_bytes());
}

auto sha256_digest(slice<u8> input) -> CryptoResult<Sha256Digest> {
  return Ok(Sha256Digest::from_bytes(rstd_try(sha256(input))));
}

auto sha256_digest(ref<str> input) -> CryptoResult<Sha256Digest> {
  return sha256_digest(input.as_bytes());
}

} // namespace licrypto

export namespace rstd {

template <> struct Impl<str_::FromStr, licrypto::Sha256Digest> {
  using Err = licrypto::Sha256DigestParseError;

  static auto from_str(ref<str> value) -> Result<licrypto::Sha256Digest, Err> {
    return licrypto::Sha256Digest::parse_hex(value);
  }
};

template <> struct Impl<convert::TryFrom<ref<str>>, licrypto::Sha256Digest> {
  using Error = licrypto::Sha256DigestParseError;

  static auto try_from(ref<str> value)
      -> Result<licrypto::Sha256Digest, Error> {
    return rstd::from_str<licrypto::Sha256Digest>(value);
  }
};

template <>
struct Impl<fmt::Display, licrypto::Sha256Digest>
    : ImplBase<licrypto::Sha256Digest> {
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
struct Impl<fmt::Debug, licrypto::Sha256Digest>
    : ImplBase<licrypto::Sha256Digest> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    return as<fmt::Display>(this->self()).fmt(formatter);
  }
};

template <>
struct Impl<fmt::Display, licrypto::Sha256DigestParseError>
    : ImplBase<licrypto::Sha256DigestParseError> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    const auto &error = this->self();
    if (error.is_Length()) {
      return formatter.write_fmt(fmt::Arguments::make(
          "SHA-256 digest must contain 64 hexadecimal characters; found {}",
          error.as_Length().actual));
    }
    return formatter.write_fmt(fmt::Arguments::make(
        "SHA-256 digest contains a non-hexadecimal character at byte {}",
        error.as_Character().index));
  }
};

template <>
struct Impl<fmt::Debug, licrypto::Sha256DigestParseError>
    : ImplBase<licrypto::Sha256DigestParseError> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    return as<fmt::Display>(this->self()).fmt(formatter);
  }
};

template <>
struct Impl<error::Error, licrypto::Sha256DigestParseError>
    : DefaultInImpl<error::Error, licrypto::Sha256DigestParseError> {};

template <>
struct Impl<hash::Hash, licrypto::Sha256Digest>
    : ImplBase<licrypto::Sha256Digest> {
  template <typename H>
    requires Impled<H, hash::Hasher>
  void hash(H &state) const noexcept {
    rstd::as<hash::Hasher>(state).write(this->self().as_bytes());
  }
};

} // namespace rstd
