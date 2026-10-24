module;
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <rstd/macro.hpp>
module licrypto;
import :tls.context;
import :tls.backend;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;
using rstd::bytes::Bytes;
namespace licrypto::tls {
using rstd::sync::Arc;
IdentityState::~IdentityState() {
  for (auto *certificate : chain)
    X509_free(certificate);
  EVP_PKEY_free(key);
}
ContextState::~ContextState() { SSL_CTX_free(handle); }
Identity::Identity(Arc<IdentityState> state) : state_(rstd::move(state)) {}
Identity::Identity(Identity &&) noexcept = default;
auto Identity::operator=(Identity &&) noexcept -> Identity & = default;
Identity::~Identity() = default;
auto Identity::clone() const -> Identity { return Identity(state_.clone()); }
Context::Context(Arc<ContextState> state) : state_(rstd::move(state)) {}
Context::Context(Context &&) noexcept = default;
auto Context::operator=(Context &&) noexcept -> Context & = default;
Context::~Context() = default;
auto Context::clone() const -> Context { return Context(state_.clone()); }
auto Context::is_client() const -> bool { return state_->client; }
auto Context::maximum_plaintext() const -> usize {
  return state_->parameters.maximum_plaintext;
}

auto ServerName::dns(ref<str> name) -> CryptoResult<ServerName> {
  if (rstd::net::Ipv4Addr::parse(name).is_ok() ||
      rstd::net::Ipv6Addr::parse(name).is_ok())
    return Err(
        Error::Configuration("IP identities require ServerName::ip"_Str));
  if (name.is_empty() || name.len() > usize(253))
    return Err(Error::Configuration("invalid TLS DNS name length"_Str));
  usize label{};
  bool hyphen = false;
  for (auto byte : name.as_bytes()) {
    auto c = byte.to_primitive();
    if (c == '.') {
      if (label == usize() || hyphen)
        return Err(Error::Configuration("invalid TLS DNS label"_Str));
      label = usize();
      hyphen = false;
      continue;
    }
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-'))
      return Err(
          Error::Configuration("TLS DNS names must use ASCII A-labels"_Str));
    if (c == '-' && label == usize())
      return Err(Error::Configuration("TLS DNS label begins with hyphen"_Str));
    if (++label > usize(63))
      return Err(Error::Configuration("TLS DNS label is too long"_Str));
    hyphen = c == '-';
  }
  if (label == usize() || hyphen)
    return Err(Error::Configuration("invalid TLS DNS label"_Str));
  return Ok(ServerName(String::make(name), false));
}
auto ServerName::ip(rstd::net::Ipv4Addr address) -> ServerName {
  auto result = ServerName({}, true);
  result.address_length_ = usize(4);
  for (usize i{}; i < usize(4); ++i)
    result.address_[i] = address.octet(i);
  return result;
}

auto ServerName::ip(rstd::net::Ipv6Addr address) -> ServerName {
  auto result = ServerName({}, true);
  result.address_length_ = usize(16);
  for (usize i{}; i < usize(16); ++i)
    result.address_[i] = address.octet(i);
  return result;
}

auto pem_bio(const Bytes &input) -> CryptoResult<BIO *> {
  if (input.is_empty() || input.len() > usize(2147483647))
    return Err(Error::Configuration("invalid PEM input length"_Str));
  ERR_clear_error();
  auto *bio = BIO_new_mem_buf(input.as_slice().as_raw_ptr(),
                              static_cast<int>(input.len().to_primitive()));
  if (!bio)
    return Err(backend::openssl_failure("BIO_new_mem_buf"_str));
  return Ok(bio);
}
auto pem_certificates(const Bytes &certificates) -> CryptoResult<Vec<X509 *>> {
  auto *input = rstd_try(pem_bio(certificates));
  Vec<X509 *> chain;
  while (true) {
    ERR_clear_error();
    auto *certificate = PEM_read_bio_X509(input, nullptr, nullptr, nullptr);
    if (certificate) {
      chain.push(rstd::move(certificate));
      continue;
    }
    auto code = ERR_peek_last_error();
    if (BIO_eof(input) && ERR_GET_LIB(code) == ERR_LIB_PEM &&
        ERR_GET_REASON(code) == PEM_R_NO_START_LINE) {
      ERR_clear_error();
      break;
    }
    auto error = backend::openssl_failure("PEM_read_bio_X509"_str);
    BIO_free(input);
    for (auto *item : chain)
      X509_free(item);
    return Err(rstd::move(error));
  }
  BIO_free(input);
  if (chain.is_empty())
    return Err(Error::Configuration("input contains no PEM certificate"_Str));
  return Ok(rstd::move(chain));
}
auto Identity::from_pem(Bytes certificates, Bytes key)
    -> CryptoResult<Identity> {
  auto chain = rstd_try(pem_certificates(certificates));
  auto key_input = pem_bio(key);
  if (key_input.is_err()) {
    for (auto *certificate : chain)
      X509_free(certificate);
    return Err(rstd::move(key_input).unwrap_err());
  }
  auto *key_bio = rstd::move(key_input).unwrap();
  auto *private_key = PEM_read_bio_PrivateKey(
      key_bio, nullptr, [](char *, int, int, void *) -> int { return 0; },
      nullptr);
  if (!private_key) {
    auto error = backend::openssl_failure("PEM_read_bio_PrivateKey"_str);
    BIO_free(key_bio);
    for (auto *certificate : chain)
      X509_free(certificate);
    return Err(rstd::move(error));
  }
  BIO_free(key_bio);
  auto state = Arc<IdentityState>::make(rstd::move(chain), private_key);
  ERR_clear_error();
  if (X509_check_private_key(state->chain[usize()], private_key) != 1)
    return Err(backend::openssl_failure("X509_check_private_key"_str));
  return Ok(Identity(rstd::move(state)));
}

int select_alpn(SSL *, const unsigned char **selected,
                unsigned char *selected_length, const unsigned char *input,
                unsigned input_length, void *argument) {
  auto &state = *static_cast<ContextState *>(argument);
  unsigned char *protocol = nullptr;
  auto rc = SSL_select_next_proto(
      &protocol, selected_length,
      reinterpret_cast<const unsigned char *>(
          state.alpn.as_slice().as_raw_ptr()),
      static_cast<unsigned>(state.alpn.len().to_primitive()), input,
      input_length);
  if (rc != OPENSSL_NPN_NEGOTIATED)
    return state.parameters.require_application_protocol
               ? SSL_TLSEXT_ERR_ALERT_FATAL
               : SSL_TLSEXT_ERR_NOACK;
  *selected = protocol;
  return SSL_TLSEXT_ERR_OK;
}
auto make_context(Parameters parameters, bool client)
    -> CryptoResult<Arc<ContextState>> {
  if (parameters.minimum > parameters.maximum ||
      parameters.bio_capacity == usize() ||
      parameters.bio_capacity > usize(1048576) ||
      parameters.maximum_plaintext == usize() ||
      parameters.maximum_plaintext > usize(65536) ||
      parameters.maximum_certificate_bytes == usize() ||
      parameters.maximum_certificate_bytes > usize(16777216))
    return Err(
        Error::Configuration("invalid TLS protocol or buffer limits"_Str));
  if (parameters.require_application_protocol &&
      parameters.application_protocols.is_empty())
    return Err(Error::Configuration("required ALPN list is empty"_Str));
  ERR_clear_error();
  auto *handle =
      SSL_CTX_new(client ? TLS_client_method() : TLS_server_method());
  if (!handle)
    return Err(backend::openssl_failure("SSL_CTX_new"_str));
  auto state = Arc<ContextState>::make(handle, rstd::move(parameters), client);
  auto minimum = state->parameters.minimum == Version::Tls12 ? TLS1_2_VERSION
                                                             : TLS1_3_VERSION;
  auto maximum = state->parameters.maximum == Version::Tls12 ? TLS1_2_VERSION
                                                             : TLS1_3_VERSION;
  if (SSL_CTX_set_min_proto_version(handle, minimum) != 1 ||
      SSL_CTX_set_max_proto_version(handle, maximum) != 1)
    return Err(backend::openssl_failure("SSL_CTX_set_proto_version"_str));
  SSL_CTX_set_mode(handle, SSL_MODE_ENABLE_PARTIAL_WRITE);
  SSL_CTX_set_session_cache_mode(handle, SSL_SESS_CACHE_OFF);
  SSL_CTX_set_options(handle, SSL_OP_NO_TICKET);
  if (!client && SSL_CTX_set_num_tickets(handle, 0) != 1)
    return Err(backend::openssl_failure("SSL_CTX_set_num_tickets"_str));
  SSL_CTX_set_options(handle, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
  SSL_CTX_set_max_cert_list(
      handle, static_cast<long>(
                  state->parameters.maximum_certificate_bytes.to_primitive()));
  SSL_CTX_set_verify(handle, client ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                     nullptr);
  for (const auto &protocol : state->parameters.application_protocols) {
    if (protocol.is_empty() || protocol.len() > usize(255) ||
        state->alpn.len() + protocol.len() + usize(1) > usize(65535))
      return Err(Error::Configuration("invalid ALPN protocol length"_Str));
    state->alpn.push(u8(protocol.len().to_primitive()));
    state->alpn.extend_from_slice(protocol.as_str().as_bytes());
  }
  if (!state->alpn.is_empty()) {
    if (client) {
      if (SSL_CTX_set_alpn_protos(
              handle,
              reinterpret_cast<const unsigned char *>(
                  state->alpn.as_slice().as_raw_ptr()),
              static_cast<unsigned>(state->alpn.len().to_primitive())) != 0)
        return Err(backend::openssl_failure("SSL_CTX_set_alpn_protos"_str));
    } else
      SSL_CTX_set_alpn_select_cb(handle, select_alpn,
                                 state.as_ptr().as_raw_ptr());
  }
  return Ok(rstd::move(state));
}
auto install_identity(SSL_CTX *handle, const IdentityState &identity)
    -> CryptoResult<empty> {
  if (SSL_CTX_use_certificate(handle, identity.chain[usize()]) != 1 ||
      SSL_CTX_use_PrivateKey(handle, identity.key) != 1 ||
      SSL_CTX_check_private_key(handle) != 1)
    return Err(backend::openssl_failure("SSL_CTX_use_identity"_str));
  for (usize i(1); i < identity.chain.len(); ++i) {
    if (SSL_CTX_add1_chain_cert(handle, identity.chain[i]) != 1)
      return Err(backend::openssl_failure("SSL_CTX_add1_chain_cert"_str));
  }
  return Ok(empty{});
}
auto Context::client(Trust trust, Parameters parameters,
                     const Identity *identity) -> CryptoResult<Context> {
  if (!trust.verify_peer && parameters.verify_hostname)
    return Err(Error::Configuration(
        "hostname verification requires peer verification"_Str));
  auto state = rstd_try(make_context(rstd::move(parameters), true));
  SSL_CTX_set_verify(state->handle,
                     trust.verify_peer ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
                     nullptr);
  if (identity)
    rstd_try(install_identity(state->handle, *identity->state_));
  if (trust.use_system_roots &&
      SSL_CTX_set_default_verify_paths(state->handle) != 1)
    return Err(
        backend::openssl_failure("SSL_CTX_set_default_verify_paths"_str));
  for (const auto &pem : trust.ca_pem) {
    auto certificates = rstd_try(pem_certificates(pem));
    Option<Error> failure;
    for (auto *certificate : certificates) {
      if (!failure) {
        ERR_clear_error();
        if (X509_STORE_add_cert(SSL_CTX_get_cert_store(state->handle),
                                certificate) != 1)
          failure = Some(backend::openssl_failure("X509_STORE_add_cert"_str));
      }
      X509_free(certificate);
    }
    if (failure)
      return Err(rstd::move(failure).unwrap());
  }
  return Ok(Context(rstd::move(state)));
}
auto Context::server(const Identity &identity, Parameters parameters)
    -> CryptoResult<Context> {
  auto state = rstd_try(make_context(rstd::move(parameters), false));
  rstd_try(install_identity(state->handle, *identity.state_));
  return Ok(Context(rstd::move(state)));
}
} // namespace licrypto::tls
