module licrypto:backend.openssl.error;
import rstd;
import :error;
namespace licrypto::backend {
auto openssl_failure(rstd::ref<rstd::str> operation, bool unavailable = false)
    -> Error;
}
