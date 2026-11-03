export module licrypto:adler32;
import rstd;

using namespace rstd::prelude;

export namespace licrypto {

class Adler32 {
  unsigned first_ = 1;
  unsigned second_ = 0;

public:
  static constexpr auto make() noexcept -> Adler32 { return {}; }
  void update(slice<u8> input) noexcept {
    auto *bytes = input.as_raw_ptr();
    auto size = input.len().to_primitive();
    while (size != 0) {
      auto count = size < 5552 ? size : 5552;
      size -= count;
      while (count-- != 0) {
        first_ += static_cast<unsigned char>(*bytes++);
        second_ += first_;
      }
      first_ %= 65521u;
      second_ %= 65521u;
    }
  }
  constexpr auto value() const noexcept -> u32 {
    return u32((second_ << 16) | first_);
  }
  constexpr void reset() noexcept {
    first_ = 1;
    second_ = 0;
  }
};

inline auto adler32(slice<u8> input) noexcept -> u32 {
  auto state = Adler32::make();
  state.update(input);
  return state.value();
}

} // namespace licrypto
