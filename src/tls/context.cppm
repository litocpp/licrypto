export module licrypto:tls.context;
export import :tls.types;
import rstd;
using namespace rstd::prelude;
namespace licrypto::tls {
struct IdentityState;
struct ContextState;
} // namespace licrypto::tls
export namespace licrypto::tls {
class Session;
class Identity {
  rstd::sync::Arc<IdentityState> state_;
  explicit Identity(rstd::sync::Arc<IdentityState> state);
  friend class Context;

public:
  Identity(const Identity &) = delete;
  auto operator=(const Identity &) -> Identity & = delete;
  Identity(Identity &&) noexcept;
  auto operator=(Identity &&) noexcept -> Identity &;
  ~Identity();
  static auto from_pem(rstd::bytes::Bytes certificate_chain,
                       rstd::bytes::Bytes private_key)
      -> CryptoResult<Identity>;
  auto clone() const -> Identity;
};
class Context {
  rstd::sync::Arc<ContextState> state_;
  explicit Context(rstd::sync::Arc<ContextState> state);
  friend class Session;

public:
  Context(const Context &) = delete;
  auto operator=(const Context &) -> Context & = delete;
  Context(Context &&) noexcept;
  auto operator=(Context &&) noexcept -> Context &;
  ~Context();
  static auto client(Trust trust = {}, Parameters parameters = {})
      -> CryptoResult<Context>;
  static auto server(const Identity &identity, Parameters parameters = {})
      -> CryptoResult<Context>;
  auto clone() const -> Context;
  auto is_client() const -> bool;
  auto maximum_plaintext() const -> usize;
};
} // namespace licrypto::tls
