module;
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <rstd/macro.hpp>
module licrypto;
import :tls.session;
import :tls.backend;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;
using rstd::bytes::Bytes;
using rstd::bytes::BytesMut;
namespace licrypto::tls {
SessionState::~SessionState() {
  SSL_free(ssl);
  BIO_free(io);
}
Session::Session(Session &&other) noexcept
    : state_(rstd::exchange(other.state_, nullptr)) {}
auto Session::operator=(Session &&other) noexcept -> Session & {
  if (this != &other) {
    delete static_cast<SessionState *>(state_);
    state_ = rstd::exchange(other.state_, nullptr);
  }
  return *this;
}
Session::~Session() { delete static_cast<SessionState *>(state_); }

auto make_session(rstd::sync::Arc<ContextState> context)
    -> CryptoResult<void *> {
  auto *state = new SessionState(rstd::move(context));
  ERR_clear_error();
  state->ssl = SSL_new(state->context->handle);
  if (!state->ssl) {
    auto error = backend::openssl_failure("SSL_new"_str);
    delete state;
    return Err(rstd::move(error));
  }
  BIO *internal = nullptr;
  auto capacity = state->context->parameters.bio_capacity.to_primitive();
  if (BIO_new_bio_pair(&internal, capacity, &state->io, capacity) != 1) {
    auto error = backend::openssl_failure("BIO_new_bio_pair"_str);
    delete state;
    return Err(rstd::move(error));
  }
  SSL_set0_rbio(state->ssl, internal);
  if (BIO_up_ref(internal) != 1) {
    auto error = backend::openssl_failure("BIO_up_ref"_str);
    delete state;
    return Err(rstd::move(error));
  }
  SSL_set0_wbio(state->ssl, internal);
  if (state->context->client)
    SSL_set_connect_state(state->ssl);
  else
    SSL_set_accept_state(state->ssl);
  return Ok(static_cast<void *>(state));
}
auto Session::client(const Context &context, ServerName name)
    -> CryptoResult<Session> {
  if (!context.is_client())
    return Err(Error::Configuration("server context used for TLS client"_Str));
  auto session = Session(rstd_try(make_session(context.state_.clone())));
  auto &state = *static_cast<SessionState *>(session.state_);
  auto *parameters = SSL_get0_param(state.ssl);
  ERR_clear_error();
  if (name.is_ip()) {
    if (X509_VERIFY_PARAM_set1_ip(parameters,
                                  reinterpret_cast<const unsigned char *>(
                                      name.address_.as_slice().as_raw_ptr()),
                                  name.address_length_.to_primitive()) != 1)
      return Err(backend::openssl_failure("X509_VERIFY_PARAM_set1_ip"_str));
  } else {
    auto encoded = rstd::ffi::CString::make(
        Vec<u8>::from(name.value_.as_str().as_bytes()));
    if (encoded.is_err())
      return Err(Error::Configuration("invalid TLS peer name"_Str));
    auto text = rstd::move(encoded).unwrap();
    X509_VERIFY_PARAM_set_hostflags(parameters,
                                    X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
    if (X509_VERIFY_PARAM_set1_host(parameters, text.as_ptr(), 0) != 1 ||
        SSL_set_tlsext_host_name(state.ssl, text.as_ptr()) != 1)
      return Err(backend::openssl_failure("configure TLS peer name"_str));
  }
  return Ok(rstd::move(session));
}
auto Session::server(const Context &context) -> CryptoResult<Session> {
  if (context.is_client())
    return Err(Error::Configuration("client context used for TLS server"_Str));
  return Ok(Session(rstd_try(make_session(context.state_.clone()))));
}
auto session_live(SessionState *state, ref<str> operation)
    -> CryptoResult<empty> {
  if (!state || state->failed)
    return Err(Error::InvalidState(String::make(operation)));
  return Ok(empty{});
}
auto ssl_failure(SessionState &state, int error, ref<str> operation) -> Error {
  state.failed = true;
  auto verification = SSL_get_verify_result(state.ssl);
  if (verification != X509_V_OK) {
    auto description = String::make();
    auto *text = X509_verify_cert_error_string(verification);
    while (*text)
      description.push_ascii(*text++);
    ERR_clear_error();
    return Error::Verification(i64(verification), rstd::move(description));
  }
  auto code = ERR_peek_last_error();
  if (error == SSL_ERROR_SYSCALL ||
      (ERR_GET_LIB(code) == ERR_LIB_SSL &&
       ERR_GET_REASON(code) == SSL_R_UNEXPECTED_EOF_WHILE_READING)) {
    ERR_clear_error();
    return Error::UnexpectedEof();
  }
  return backend::openssl_failure(operation);
}
auto ssl_pending(SessionState &state, int error) -> bool {
  if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
    state.needs_input = error == SSL_ERROR_WANT_READ;
    return true;
  }
  return false;
}
auto Session::feed(slice<u8> input) -> CryptoResult<usize> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS feed"_str));
  auto available = usize(BIO_ctrl_get_write_guarantee(state->io));
  auto count = input.len() < available ? input.len() : available;
  if (count == usize())
    return Ok(usize());
  ERR_clear_error();
  size_t transferred{};
  if (BIO_write_ex(state->io, input.as_raw_ptr(), count.to_primitive(),
                   &transferred) != 1)
    return Err(backend::openssl_failure("BIO_write_ex"_str));
  return Ok(usize(transferred));
}
auto Session::drain(usize maximum_size) -> CryptoResult<Bytes> {
  auto *state = static_cast<SessionState *>(state_);
  if (!state || maximum_size == usize())
    return Err(Error::Configuration("invalid TLS drain"_Str));
  auto available = usize(BIO_ctrl_pending(state->io));
  auto count = maximum_size < available ? maximum_size : available;
  if (count == usize())
    return Ok(Bytes{});
  auto buffer = BytesMut::with_capacity(count);
  size_t transferred{};
  ERR_clear_error();
  if (BIO_read_ex(state->io, buffer.chunk_mut().as_raw_ptr(),
                  count.to_primitive(), &transferred) != 1)
    return Err(backend::openssl_failure("BIO_read_ex"_str));
  buffer.advance_mut(usize(transferred));
  return Ok(buffer.freeze());
}
auto Session::handshake() -> CryptoResult<bool> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS handshake"_str));
  if (state->ready)
    return Ok(true);
  state->needs_input = false;
  ERR_clear_error();
  auto rc = SSL_do_handshake(state->ssl);
  if (rc != 1) {
    auto error = SSL_get_error(state->ssl, rc);
    if (ssl_pending(*state, error))
      return Ok(false);
    return Err(ssl_failure(*state, error, "SSL_do_handshake"_str));
  }
  const unsigned char *selected = nullptr;
  unsigned length{};
  SSL_get0_alpn_selected(state->ssl, &selected, &length);
  if (state->context->parameters.require_application_protocol && length == 0) {
    state->failed = true;
    return Err(Error::Protocol("required ALPN was not negotiated"_Str));
  }
  state->ready = true;
  return Ok(true);
}
auto Session::read(usize maximum_size) -> CryptoResult<Option<Bytes>> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS read"_str));
  if (!state->ready || maximum_size == usize())
    return Err(Error::InvalidState(
        "TLS read before handshake or with empty buffer"_Str));
  auto count = maximum_size < state->context->parameters.maximum_plaintext
                   ? maximum_size
                   : state->context->parameters.maximum_plaintext;
  auto buffer = BytesMut::with_capacity(count);
  size_t transferred{};
  state->needs_input = false;
  ERR_clear_error();
  auto rc = SSL_read_ex(state->ssl, buffer.chunk_mut().as_raw_ptr(),
                        count.to_primitive(), &transferred);
  if (rc != 1) {
    auto error = SSL_get_error(state->ssl, rc);
    if (error == SSL_ERROR_ZERO_RETURN)
      return Ok(Some(Bytes{}));
    if (ssl_pending(*state, error))
      return Ok(None<Bytes>());
    return Err(ssl_failure(*state, error, "SSL_read_ex"_str));
  }
  buffer.advance_mut(usize(transferred));
  return Ok(Some(buffer.freeze()));
}
auto Session::start_write(Bytes input) -> CryptoResult<empty> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS start_write"_str));
  if (!state->ready || (SSL_get_shutdown(state->ssl) & SSL_SENT_SHUTDOWN))
    return Err(Error::Closed());
  if (state->writing)
    return Err(Error::Busy());
  auto length = input.len() < state->context->parameters.maximum_plaintext
                    ? input.len()
                    : state->context->parameters.maximum_plaintext;
  state->write_length = length;
  state->writing = Some(input.slice(usize(), length));
  return Ok(empty{});
}
auto Session::write() -> CryptoResult<Option<usize>> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS write"_str));
  if (!state->writing)
    return Err(Error::InvalidState("TLS write has no owned input"_Str));
  if (state->write_length == usize()) {
    state->writing = None();
    return Ok(Some(usize()));
  }
  state->needs_input = false;
  size_t transferred{};
  ERR_clear_error();
  auto rc = SSL_write_ex(state->ssl, state->writing->as_slice().as_raw_ptr(),
                         state->write_length.to_primitive(), &transferred);
  if (rc != 1) {
    auto error = SSL_get_error(state->ssl, rc);
    if (ssl_pending(*state, error))
      return Ok(None<usize>());
    return Err(ssl_failure(*state, error, "SSL_write_ex"_str));
  }
  state->writing = None();
  return Ok(Some(usize(transferred)));
}
auto Session::shutdown() -> CryptoResult<bool> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS shutdown"_str));
  if (!state->ready || state->writing)
    return Err(
        Error::InvalidState("TLS shutdown before pending write completes"_Str));
  state->needs_input = false;
  ERR_clear_error();
  auto rc = SSL_shutdown(state->ssl);
  if (rc == 1)
    return Ok(true);
  if (rc == 0) {
    state->needs_input = true;
    return Ok(false);
  }
  auto error = SSL_get_error(state->ssl, rc);
  if (ssl_pending(*state, error))
    return Ok(false);
  return Err(ssl_failure(*state, error, "SSL_shutdown"_str));
}
auto Session::transport_eof() -> CryptoResult<empty> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS transport EOF"_str));
  BIO_shutdown_wr(state->io);
  return Ok(empty{});
}
auto Session::progress() const -> Progress {
  auto *state = static_cast<SessionState *>(state_);
  if (!state)
    return {false, false, false, false, usize(), usize()};
  auto shutdown = SSL_get_shutdown(state->ssl);
  return {state->ready,
          (shutdown & SSL_RECEIVED_SHUTDOWN) != 0,
          (shutdown & SSL_SENT_SHUTDOWN) != 0,
          state->needs_input,
          usize(BIO_ctrl_pending(state->io)),
          usize(BIO_ctrl_get_write_guarantee(state->io))};
}
auto Session::application_protocol() const -> CryptoResult<Bytes> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS application protocol"_str));
  if (!state->ready)
    return Err(
        Error::InvalidState("TLS application protocol before handshake"_Str));
  const unsigned char *selected = nullptr;
  unsigned length{};
  SSL_get0_alpn_selected(state->ssl, &selected, &length);
  return Ok(Bytes::copy_from_slice(slice<u8>::from_raw_parts(
      reinterpret_cast<const rstd::byte *>(selected), usize(length))));
}
auto Session::negotiated_version() const -> CryptoResult<Version> {
  auto *state = static_cast<SessionState *>(state_);
  rstd_try(session_live(state, "TLS negotiated version"_str));
  if (!state->ready)
    return Err(
        Error::InvalidState("TLS negotiated version before handshake"_Str));
  return Ok(SSL_version(state->ssl) == TLS1_3_VERSION ? Version::Tls13
                                                      : Version::Tls12);
}
} // namespace licrypto::tls
