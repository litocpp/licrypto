module;
#include <rstd/macro.hpp>

export module licrypto:sha1;

import rstd;
export import :error;
import :backend.digest;

using namespace rstd::prelude;
using rstd::string::String;

export namespace licrypto {

class Sha1 {
  backend::DigestState<backend::Algorithm::Sha1, 20> state_;
  explicit Sha1(backend::DigestState<backend::Algorithm::Sha1, 20> state)
      : state_(rstd::move(state)) {}

public:
  Sha1(const Sha1 &) = delete;
  auto operator=(const Sha1 &) -> Sha1 & = delete;
  Sha1(Sha1 &&) noexcept = default;
  auto operator=(Sha1 &&) noexcept -> Sha1 & = default;
  static auto make() -> CryptoResult<Sha1> {
    auto state =
        rstd_try((backend::DigestState<backend::Algorithm::Sha1, 20>::make()));
    return Ok(Sha1(rstd::move(state)));
  }
  auto update(slice<u8> input) -> CryptoResult<empty> {
    return state_.update(input);
  }
  auto finalize() && -> CryptoResult<array<u8, 20>> {
    return rstd::move(state_).finalize();
  }
};

auto sha1(slice<u8> input) -> CryptoResult<array<u8, 20>> {
  auto state = rstd_try(Sha1::make());
  rstd_try(state.update(input));
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

auto sha1_hex(slice<u8> input) -> CryptoResult<String> {
  return Ok(sha1_hex(rstd_try(sha1(input))));
}

auto sha1_hex(ref<str> input) -> CryptoResult<String> {
  return sha1_hex(input.as_bytes());
}

} // namespace licrypto
