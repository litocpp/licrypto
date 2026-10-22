module;
#include <rstd/enum.hpp>

export module licrypto:error;
import rstd;

using namespace rstd::prelude;
using namespace rstd::literals;

export namespace licrypto {

enum class BackendKind { Builtin, OpenSsl };

struct BackendFailure {
  BackendKind backend;
  u64 code;
  String operation;
  String message;

  auto clone() const -> BackendFailure {
    return {backend, code, operation.clone(), message.clone()};
  }
};

class Error {
  RSTD_ENUM(Error, (Backend, (BackendFailure failure;)),
            (AlgorithmUnavailable, (BackendFailure failure;)),
            (InvalidState, (String operation;)),
            (Configuration, (String message;)),
            (Verification, (i64 code; String message;)),
            (Protocol, (String message;)), (Io, (rstd::io::Error cause;)),
            (UnexpectedEof, ()), (Closed, ()), (Busy, ()), (Timeout, ()))

public:
  auto clone() const -> Error {
    if (is_Backend())
      return Backend(as_Backend().failure.clone());
    if (is_AlgorithmUnavailable())
      return AlgorithmUnavailable(as_AlgorithmUnavailable().failure.clone());
    if (is_InvalidState())
      return InvalidState(as_InvalidState().operation.clone());
    if (is_Configuration())
      return Configuration(as_Configuration().message.clone());
    if (is_Verification())
      return Verification(as_Verification().code,
                          as_Verification().message.clone());
    if (is_Protocol())
      return Protocol(as_Protocol().message.clone());
    if (is_Io())
      return Io(as_Io().cause);
    if (is_UnexpectedEof())
      return UnexpectedEof();
    if (is_Busy())
      return Busy();
    if (is_Timeout())
      return Timeout();
    return Closed();
  }
};

template <class T> using CryptoResult = Result<T, Error>;

} // namespace licrypto

export namespace rstd {
template <>
struct Impl<fmt::Display, licrypto::Error> : ImplBase<licrypto::Error> {
  auto fmt(fmt::Formatter &f) const -> bool {
    const auto &e = this->self();
    if (e.is_Backend() || e.is_AlgorithmUnavailable()) {
      const auto &d = e.is_Backend() ? e.as_Backend().failure
                                     : e.as_AlgorithmUnavailable().failure;
      return f.write_fmt(fmt::Arguments::make("{}: {} (code {})", d.operation,
                                              d.message, d.code));
    }
    if (e.is_InvalidState())
      return f.write_fmt(fmt::Arguments::make("invalid state for {}",
                                              e.as_InvalidState().operation));
    if (e.is_Configuration())
      return f.write_fmt(
          fmt::Arguments::make("{}", e.as_Configuration().message));
    if (e.is_Verification())
      return f.write_fmt(fmt::Arguments::make(
          "certificate verification failed: {}", e.as_Verification().message));
    if (e.is_Protocol())
      return f.write_fmt(fmt::Arguments::make("TLS protocol error: {}",
                                              e.as_Protocol().message));
    if (e.is_Io())
      return f.write_fmt(fmt::Arguments::make("{}", e.as_Io().cause));
    if (e.is_UnexpectedEof())
      return f.write_str("TLS transport ended without close_notify"_str);
    if (e.is_Busy())
      return f.write_str("TLS operation already in progress"_str);
    if (e.is_Timeout())
      return f.write_str("TLS operation timed out"_str);
    return f.write_str("TLS connection closed"_str);
  }
};
template <>
struct Impl<fmt::Debug, licrypto::Error> : Impl<fmt::Display, licrypto::Error> {
};
template <>
struct Impl<error::Error, licrypto::Error>
    : DefaultInImpl<error::Error, licrypto::Error> {
  auto source() const noexcept -> Option<error::ErrorRef> {
    if (this->self().is_Io())
      return Some(dyn<error::Error>::from_ref(this->self().as_Io().cause));
    return None();
  }
};
} // namespace rstd
