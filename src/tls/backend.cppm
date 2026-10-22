module;
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
module licrypto:tls.backend;
import rstd;
import :tls.context;
import :tls.session;
import :backend.openssl.error;
using namespace rstd::prelude;
namespace licrypto::tls {
struct IdentityState {
  Vec<X509 *> chain;
  EVP_PKEY *key = nullptr;
  IdentityState(Vec<X509 *> chain, EVP_PKEY *key)
      : chain(rstd::move(chain)), key(key) {}
  ~IdentityState();
};
struct ContextState {
  SSL_CTX *handle;
  Parameters parameters;
  Vec<u8> alpn;
  bool client;
  ContextState(SSL_CTX *handle, Parameters parameters, bool client)
      : handle(handle), parameters(rstd::move(parameters)), client(client) {}
  ~ContextState();
};
struct SessionState {
  rstd::sync::Arc<ContextState> context;
  SSL *ssl = nullptr;
  BIO *io = nullptr;
  Option<rstd::bytes::Bytes> writing;
  usize write_length{};
  bool ready = false;
  bool failed = false;
  bool needs_input = false;
  SessionState(rstd::sync::Arc<ContextState> context)
      : context(rstd::move(context)) {}
  ~SessionState();
};
auto make_context(Parameters parameters, bool client)
    -> CryptoResult<rstd::sync::Arc<ContextState>>;
auto make_session(rstd::sync::Arc<ContextState> context)
    -> CryptoResult<void *>;
} // namespace licrypto::tls
