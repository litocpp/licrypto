module licrypto:backend.native;
import rstd;
import :error;
import :backend.algorithm;
import :backend.native.md5;
import :backend.native.sha1;
import :backend.native.sha256;
import :backend.native.sha512;
using namespace rstd::prelude;
using namespace rstd::literals;
namespace licrypto::backend {
template <Algorithm A> struct NativeType;
template <> struct NativeType<Algorithm::Md5> {
  using Type = BuiltinMd5;
};
template <> struct NativeType<Algorithm::Sha1> {
  using Type = BuiltinSha1;
};
template <> struct NativeType<Algorithm::Sha256> {
  using Type = BuiltinSha256;
};
template <> struct NativeType<Algorithm::Sha512> {
  using Type = BuiltinSha512;
};
template <Algorithm A, rstd::size_t N> class DigestState {
  using State = typename NativeType<A>::Type;
  State state_;
  bool active_ = true;
  explicit DigestState(State state) : state_(rstd::move(state)) {}

public:
  DigestState(const DigestState &) = delete;
  auto operator=(const DigestState &) -> DigestState & = delete;
  DigestState(DigestState &&other) noexcept
      : state_(rstd::move(other.state_)),
        active_(rstd::exchange(other.active_, false)) {}
  auto operator=(DigestState &&other) noexcept -> DigestState & {
    if (this != &other) {
      state_ = rstd::move(other.state_);
      active_ = rstd::exchange(other.active_, false);
    }
    return *this;
  }
  static auto make() -> CryptoResult<DigestState> {
    return Ok(DigestState(State::make()));
  }
  auto update(slice<u8> input) -> CryptoResult<empty> {
    if (!active_)
      return Err(Error::InvalidState("digest update"_Str));
    state_.update(input);
    return Ok(empty{});
  }
  auto finalize() && -> CryptoResult<array<u8, N>> {
    if (!rstd::exchange(active_, false))
      return Err(Error::InvalidState("digest finalize"_Str));
    return Ok(rstd::move(state_).finalize());
  }
};
} // namespace licrypto::backend
