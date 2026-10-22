module;
#include <rstd/macro.hpp>

export module licrypto:md5;
import rstd;
export import :error;
import :backend.digest;

using namespace rstd::prelude;
using rstd::string::String;

export namespace licrypto {

class Md5 {
  backend::DigestState<backend::Algorithm::Md5, 16> state_;
  explicit Md5(backend::DigestState<backend::Algorithm::Md5, 16> state)
      : state_(rstd::move(state)) {}

public:
  Md5(const Md5 &) = delete;
  auto operator=(const Md5 &) -> Md5 & = delete;
  Md5(Md5 &&) noexcept = default;
  auto operator=(Md5 &&) noexcept -> Md5 & = default;
  static auto make() -> CryptoResult<Md5> {
    auto state =
        rstd_try((backend::DigestState<backend::Algorithm::Md5, 16>::make()));
    return Ok(Md5(rstd::move(state)));
  }
  auto update(slice<u8> input) -> CryptoResult<empty> {
    return state_.update(input);
  }
  auto finalize() && -> CryptoResult<array<u8, 16>> {
    return rstd::move(state_).finalize();
  }
};

auto md5(slice<u8> input) -> CryptoResult<array<u8, 16>> {
  auto state = rstd_try(Md5::make());
  rstd_try(state.update(input));
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
auto md5_hex(slice<u8> input) -> CryptoResult<String> {
  return Ok(md5_hex(rstd_try(md5(input))));
}
auto md5_hex(ref<str> text) -> CryptoResult<String> {
  return md5_hex(text.as_bytes());
}

} // namespace licrypto
