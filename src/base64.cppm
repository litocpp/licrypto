module;
#include <rstd/enum.hpp>

export module licrypto:base64;

import rstd;

using namespace rstd::prelude;
using ::alloc::string::String;
using ::alloc::vec::Vec;

export namespace licrypto {

class Base64DecodeError {
  RSTD_ENUM(Base64DecodeError, (Length, (usize actual;)),
            (Character, (usize index;)), (Padding, (usize index;)),
            (TrailingBits, (usize index;)))
};

auto base64_encode(slice<u8> input) -> String {
  static constexpr char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  auto result = String::make();
  const auto complete_groups = input.len() / usize(3);
  result.reserve(complete_groups * usize(4) +
                 (input.len() % usize(3) == usize() ? usize() : usize(4)));

  usize position{};
  while (input.len() - position >= usize(3)) {
    const auto first = static_cast<uint32_t>(input[position].to_primitive());
    const auto second =
        static_cast<uint32_t>(input[position + usize(1)].to_primitive());
    const auto third =
        static_cast<uint32_t>(input[position + usize(2)].to_primitive());
    result.push_ascii(alphabet[first >> 2u]);
    result.push_ascii(alphabet[((first & 0x03u) << 4u) | (second >> 4u)]);
    result.push_ascii(alphabet[((second & 0x0fu) << 2u) | (third >> 6u)]);
    result.push_ascii(alphabet[third & 0x3fu]);
    position += usize(3);
  }

  const auto remaining = input.len() - position;
  if (remaining == usize(1)) {
    const auto first = static_cast<uint32_t>(input[position].to_primitive());
    result.push_ascii(alphabet[first >> 2u]);
    result.push_ascii(alphabet[(first & 0x03u) << 4u]);
    result.push_ascii('=');
    result.push_ascii('=');
  } else if (remaining == usize(2)) {
    const auto first = static_cast<uint32_t>(input[position].to_primitive());
    const auto second =
        static_cast<uint32_t>(input[position + usize(1)].to_primitive());
    result.push_ascii(alphabet[first >> 2u]);
    result.push_ascii(alphabet[((first & 0x03u) << 4u) | (second >> 4u)]);
    result.push_ascii(alphabet[(second & 0x0fu) << 2u]);
    result.push_ascii('=');
  }
  return result;
}

auto base64_encode(ref<str> input) -> String {
  return base64_encode(input.as_bytes());
}

auto base64_decode(ref<str> input) -> Result<Vec<u8>, Base64DecodeError> {
  if (input.len() % usize(4) != usize())
    return Err(Base64DecodeError::Length(input.len()));

  auto value_of = [](u8 value) -> Option<uint32_t> {
    const auto byte = value.to_primitive();
    if (byte >= 'A' && byte <= 'Z')
      return Some(static_cast<uint32_t>(byte - 'A'));
    if (byte >= 'a' && byte <= 'z')
      return Some(static_cast<uint32_t>(byte - 'a' + 26));
    if (byte >= '0' && byte <= '9')
      return Some(static_cast<uint32_t>(byte - '0' + 52));
    if (byte == '+')
      return Some(62u);
    if (byte == '/')
      return Some(63u);
    return None();
  };

  auto result = Vec<u8>::with_capacity(input.len() / usize(4) * usize(3));
  for (usize position{}; position < input.len(); position += usize(4)) {
    const auto last_group = position + usize(4) == input.len();
    const auto first_byte = input[position];
    const auto second_byte = input[position + usize(1)];
    const auto third_byte = input[position + usize(2)];
    const auto fourth_byte = input[position + usize(3)];

    if (first_byte == u8('='))
      return Err(Base64DecodeError::Padding(position));
    if (second_byte == u8('='))
      return Err(Base64DecodeError::Padding(position + usize(1)));
    auto first = value_of(first_byte);
    if (first.is_none())
      return Err(Base64DecodeError::Character(position));
    auto second = value_of(second_byte);
    if (second.is_none())
      return Err(Base64DecodeError::Character(position + usize(1)));

    if (third_byte == u8('=')) {
      if (!last_group || fourth_byte != u8('='))
        return Err(Base64DecodeError::Padding(position + usize(2)));
      if ((*second & 0x0fu) != 0u)
        return Err(Base64DecodeError::TrailingBits(position + usize(1)));
      result.push(u8((*first << 2u) | (*second >> 4u)));
      continue;
    }

    auto third = value_of(third_byte);
    if (third.is_none())
      return Err(Base64DecodeError::Character(position + usize(2)));
    result.push(u8((*first << 2u) | (*second >> 4u)));

    if (fourth_byte == u8('=')) {
      if (!last_group)
        return Err(Base64DecodeError::Padding(position + usize(3)));
      if ((*third & 0x03u) != 0u)
        return Err(Base64DecodeError::TrailingBits(position + usize(2)));
      result.push(u8(((*second & 0x0fu) << 4u) | (*third >> 2u)));
      continue;
    }

    auto fourth = value_of(fourth_byte);
    if (fourth.is_none())
      return Err(Base64DecodeError::Character(position + usize(3)));
    result.push(u8(((*second & 0x0fu) << 4u) | (*third >> 2u)));
    result.push(u8(((*third & 0x03u) << 6u) | *fourth));
  }
  return Ok(rstd::move(result));
}

} // namespace licrypto

export namespace rstd {

template <>
struct Impl<fmt::Display, licrypto::Base64DecodeError>
    : ImplBase<licrypto::Base64DecodeError> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    const auto &error = this->self();
    if (error.is_Length()) {
      return formatter.write_fmt(fmt::Arguments::make(
          "Base64 input length must be a multiple of 4; found {}",
          error.as_Length().actual));
    }
    if (error.is_Character()) {
      return formatter.write_fmt(fmt::Arguments::make(
          "Base64 input contains an invalid character at byte {}",
          error.as_Character().index));
    }
    if (error.is_Padding()) {
      return formatter.write_fmt(fmt::Arguments::make(
          "Base64 input contains invalid padding at byte {}",
          error.as_Padding().index));
    }
    return formatter.write_fmt(fmt::Arguments::make(
        "Base64 input contains non-zero trailing bits at byte {}",
        error.as_TrailingBits().index));
  }
};

template <>
struct Impl<fmt::Debug, licrypto::Base64DecodeError>
    : ImplBase<licrypto::Base64DecodeError> {
  auto fmt(fmt::Formatter &formatter) const -> bool {
    return as<fmt::Display>(this->self()).fmt(formatter);
  }
};

template <>
struct Impl<error::Error, licrypto::Base64DecodeError>
    : DefaultInImpl<error::Error, licrypto::Base64DecodeError> {};

} // namespace rstd
