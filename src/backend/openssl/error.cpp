module;
#include <openssl/err.h>
module licrypto;
import :backend.openssl.error;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;
namespace licrypto::backend {
auto openssl_failure(ref<str> operation, bool unavailable) -> Error {
  auto message = String::make();
  unsigned long first = 0;
  usize frames{};
  while (auto code = ERR_get_error()) {
    if (!first)
      first = code;
    if (frames++ >= usize(8))
      continue;
    if (!message.is_empty())
      message.push_str("; "_str);
    char text[256]{};
    ERR_error_string_n(code, text, sizeof(text));
    for (auto c : text) {
      if (!c)
        break;
      message.push_ascii(static_cast<unsigned char>(c) < 128 ? c : '?');
    }
  }
  if (message.is_empty())
    message = "OpenSSL operation failed without a diagnostic"_Str;
  auto failure = BackendFailure{BackendKind::OpenSsl, u64(first),
                                String::make(operation), rstd::move(message)};
  return unavailable ? Error::AlgorithmUnavailable(rstd::move(failure))
                     : Error::Backend(rstd::move(failure));
}
} // namespace licrypto::backend
