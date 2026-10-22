export module licrypto:tls.session;
export import :tls.context;
import rstd;
using namespace rstd::prelude;
export namespace licrypto::tls {
class Session {
  void *state_ = nullptr;
  explicit Session(void *state) : state_(state) {}

public:
  Session(const Session &) = delete;
  auto operator=(const Session &) -> Session & = delete;
  Session(Session &&) noexcept;
  auto operator=(Session &&) noexcept -> Session &;
  ~Session();
  static auto client(const Context &context, ServerName name)
      -> CryptoResult<Session>;
  static auto server(const Context &context) -> CryptoResult<Session>;
  auto feed(slice<u8> input) -> CryptoResult<usize>;
  auto drain(usize maximum_size = usize(16384))
      -> CryptoResult<rstd::bytes::Bytes>;
  auto handshake() -> CryptoResult<bool>;
  auto read(usize maximum_size) -> CryptoResult<Option<rstd::bytes::Bytes>>;
  auto start_write(rstd::bytes::Bytes input) -> CryptoResult<empty>;
  auto write() -> CryptoResult<Option<usize>>;
  auto shutdown() -> CryptoResult<bool>;
  auto transport_eof() -> CryptoResult<empty>;
  auto progress() const -> Progress;
  auto application_protocol() const -> CryptoResult<rstd::bytes::Bytes>;
  auto negotiated_version() const -> CryptoResult<Version>;
};
} // namespace licrypto::tls
