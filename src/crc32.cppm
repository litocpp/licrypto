export module licrypto:crc32;
import rstd;

using namespace rstd::prelude;

export namespace licrypto {

class Crc32Ieee {
  unsigned value_ = 0xffffffffu;

public:
  static constexpr auto make() noexcept -> Crc32Ieee { return {}; }
  void update(slice<u8> input) noexcept {
    for (auto byte : input) {
      auto value = (value_ ^ byte.to_primitive()) & 255u;
      for (unsigned bit = 0; bit < 8; ++bit)
        value = (value >> 1) ^ (0xedb88320u & (0u - (value & 1u)));
      value_ = (value_ >> 8) ^ value;
    }
  }
  constexpr auto value() const noexcept -> u32 {
    return u32(value_ ^ 0xffffffffu);
  }
  constexpr void reset() noexcept { value_ = 0xffffffffu; }
};

inline auto crc32_ieee(slice<u8> input) noexcept -> u32 {
  auto state = Crc32Ieee::make();
  state.update(input);
  return state.value();
}

} // namespace licrypto
