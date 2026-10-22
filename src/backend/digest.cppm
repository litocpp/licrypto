module licrypto:backend.digest;
#if LITO_FEAT_OPENSSL
import :backend.openssl;
#else
import :backend.native;
#endif
