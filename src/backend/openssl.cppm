module;
#include <rstd/macro.hpp>
module licrypto:backend.openssl;
import rstd;
import :error;
import :backend.algorithm;
using namespace rstd::prelude;
namespace licrypto::backend {
class OpenSslDigest {
  void *context_ = nullptr;
  void *algorithm_ = nullptr;
  OpenSslDigest(void *context, void *algorithm)
      : context_(context), algorithm_(algorithm) {}

public:
  OpenSslDigest(const OpenSslDigest &) = delete;
  auto operator=(const OpenSslDigest &) -> OpenSslDigest & = delete;
  OpenSslDigest(OpenSslDigest &&) noexcept;
  auto operator=(OpenSslDigest &&) noexcept -> OpenSslDigest &;
  ~OpenSslDigest();
  static auto make(const char *name) -> CryptoResult<OpenSslDigest>;
  auto update(slice<u8> input) -> CryptoResult<empty>;
  auto finish(void *output, usize length) -> CryptoResult<empty>;
};
class OpenSslMac {
  void *context_ = nullptr;
  void *algorithm_ = nullptr;
  OpenSslMac(void *context, void *algorithm)
      : context_(context), algorithm_(algorithm) {}

public:
  OpenSslMac(const OpenSslMac &) = delete;
  auto operator=(const OpenSslMac &) -> OpenSslMac & = delete;
  OpenSslMac(OpenSslMac &&) noexcept;
  auto operator=(OpenSslMac &&) noexcept -> OpenSslMac &;
  ~OpenSslMac();
  static auto make(slice<u8> key) -> CryptoResult<OpenSslMac>;
  auto update(slice<u8> input) -> CryptoResult<empty>;
  auto finalize() && -> CryptoResult<array<u8, 32>>;
};
template <Algorithm A, rstd::size_t N> class DigestState {
  OpenSslDigest state_;
  explicit DigestState(OpenSslDigest state) : state_(rstd::move(state)) {}

public:
  DigestState(const DigestState &) = delete;
  auto operator=(const DigestState &) -> DigestState & = delete;
  DigestState(DigestState &&) noexcept = default;
  auto operator=(DigestState &&) noexcept -> DigestState & = default;
  static auto make() -> CryptoResult<DigestState> {
    const char *name = A == Algorithm::Md5      ? "MD5"
                       : A == Algorithm::Sha1   ? "SHA1"
                       : A == Algorithm::Sha256 ? "SHA256"
                                                : "SHA512";
    return Ok(DigestState(rstd_try(OpenSslDigest::make(name))));
  }
  auto update(slice<u8> input) -> CryptoResult<empty> {
    return state_.update(input);
  }
  auto finalize() && -> CryptoResult<array<u8, N>> {
    array<u8, N> output{};
    rstd_try(state_.finish(output.as_mut_slice().as_raw_ptr(), usize(N)));
    return Ok(rstd::move(output));
  }
};
} // namespace licrypto::backend
