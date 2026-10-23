export module licrypto:tls.types;
export import :error;
import rstd;
export import rstd.net.socket_addr;
using namespace rstd::prelude;
export namespace licrypto::tls {
enum class Version { Tls12, Tls13 };
enum class CloseMode { WaitPeer, SendOnly };
struct Parameters {
  Version minimum = Version::Tls12;
  Version maximum = Version::Tls13;
  usize bio_capacity = usize(16384);
  usize maximum_plaintext = usize(16384);
  usize maximum_certificate_bytes = usize(1048576);
  Vec<String> application_protocols;
  bool require_application_protocol = false;
};
struct Trust {
  bool use_system_roots = true;
  Vec<rstd::bytes::Bytes> ca_pem;
};
class Session;
class ServerName {
  friend class Session;
  String value_;
  array<u8, 16> address_{};
  usize address_length_{};
  bool ip_;
  ServerName(String value, bool ip) : value_(rstd::move(value)), ip_(ip) {}

public:
  static auto dns(ref<str> name) -> CryptoResult<ServerName>;
  auto clone() const -> ServerName {
    ServerName result(value_.clone(), ip_);
    result.address_ = address_;
    result.address_length_ = address_length_;
    return result;
  }
  static auto ip(rstd::net::Ipv4Addr address) -> ServerName;
  auto dns_name() const -> Option<ref<str>> {
    return ip_ ? None<ref<str>>() : Some(value_.as_str());
  }
  static auto ip(rstd::net::Ipv6Addr address) -> ServerName;
  auto is_ip() const -> bool { return ip_; }
};
struct Progress {
  bool ready;
  bool peer_closed;
  bool local_closed;
  bool needs_input;
  usize pending_output;
  usize input_capacity;
};
} // namespace licrypto::tls
