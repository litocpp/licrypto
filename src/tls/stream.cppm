export module licrypto:tls.stream;
export import :tls.session;
import rstd;
using namespace rstd::prelude;
namespace licrypto::tls {
struct ConnectionOwner;
}
export namespace licrypto::tls {
struct StreamOptions {
  rstd::time::Duration handshake_timeout =
      rstd::time::Duration::from_secs(u64(10));
  rstd::time::Duration close_timeout = rstd::time::Duration::from_secs(u64(5));
  usize maximum_buffered_plaintext = usize(16384);
};
class Connector;
class Acceptor;
class Stream {
  rstd::sync::Arc<ConnectionOwner> owner_;
  explicit Stream(rstd::sync::Arc<ConnectionOwner> owner);
  friend class Connector;
  friend class Acceptor;

public:
  Stream(const Stream &) = delete;
  auto operator=(const Stream &) -> Stream & = delete;
  Stream(Stream &&) noexcept;
  auto operator=(Stream &&) noexcept -> Stream &;
  ~Stream();
  auto recv(usize maximum_size = usize(65536)) const
      -> rstd::async::coro<CryptoResult<rstd::bytes::Bytes>>;
  auto send(rstd::bytes::Bytes input) const
      -> rstd::async::coro<CryptoResult<usize>>;
  auto send_all(rstd::bytes::Bytes input) const
      -> rstd::async::coro<CryptoResult<usize>>;
  auto flush() const -> rstd::async::coro<CryptoResult<empty>>;
  auto close() && -> rstd::async::coro<CryptoResult<empty>>;
  auto application_protocol() const -> CryptoResult<rstd::bytes::Bytes>;
  auto negotiated_version() const -> CryptoResult<Version>;
};
class Connector {
  Context context_;
  StreamOptions options_;
  static auto connect_owned(Context context, rstd::net::TcpStream transport,
                            ServerName peer, StreamOptions options)
      -> rstd::async::coro<CryptoResult<Stream>>;

public:
  explicit Connector(Context context, StreamOptions options = {})
      : context_(rstd::move(context)), options_(options) {}
  auto connect(rstd::net::TcpStream transport, ServerName peer) const
      -> rstd::async::coro<CryptoResult<Stream>>;
};
class Acceptor {
  Context context_;
  StreamOptions options_;
  static auto accept_owned(Context context, rstd::net::TcpStream transport,
                           StreamOptions options)
      -> rstd::async::coro<CryptoResult<Stream>>;

public:
  explicit Acceptor(Context context, StreamOptions options = {})
      : context_(rstd::move(context)), options_(options) {}
  auto accept(rstd::net::TcpStream transport) const
      -> rstd::async::coro<CryptoResult<Stream>>;
};
} // namespace licrypto::tls
