#include <rstd/macro.hpp>
#include <rstd/test/gtest.hpp>
#if LITO_FEAT_OPENSSL
import licrypto;
import rstd;
#include "tls_material.hpp"
using namespace rstd::prelude;
using namespace rstd::literals;
using rstd::bytes::Bytes;
using namespace licrypto;
using namespace licrypto::tls;
namespace {
auto test_trust() -> Trust {
  Trust trust;
  trust.use_system_roots = false;
  trust.ca_pem.push(Bytes::copy_from_slice(licrypto_test::ca.as_bytes()));
  return trust;
}
auto test_identity(bool expired = false) -> Identity {
  return Identity::from_pem(
             Bytes::copy_from_slice(
                 (expired ? licrypto_test::expired : licrypto_test::certificate)
                     .as_bytes()),
             Bytes::copy_from_slice(licrypto_test::private_key.as_bytes()))
      .unwrap();
}
auto pump(Session &from, Session &to, usize fragment = usize(17))
    -> CryptoResult<usize> {
  auto limit = to.progress().input_capacity;
  if (limit > fragment)
    limit = fragment;
  if (limit == usize() || from.progress().pending_output == usize())
    return Ok(usize());
  auto data = rstd_try(from.drain(limit));
  auto count = rstd_try(to.feed(data.as_slice()));
  if (count != data.len())
    return Err(Error::Protocol("memory TLS transport lost bytes"_Str));
  return Ok(count);
}
auto negotiate(Session &client, Session &server) -> CryptoResult<empty> {
  for (usize attempts{}; attempts < usize(100000); ++attempts) {
    auto a = rstd_try(client.handshake());
    auto b = rstd_try(server.handshake());
    rstd_try(pump(client, server));
    rstd_try(pump(server, client));
    if (a && b && client.progress().pending_output == usize() &&
        server.progress().pending_output == usize())
      return Ok(empty{});
  }
  return Err(Error::Protocol("memory TLS handshake stalled"_Str));
}
auto transfer(Session &from, Session &to, Bytes data) -> CryptoResult<Bytes> {
  auto expected = data.len();
  rstd::bytes::BytesMut received;
  bool writing = false;
  for (usize attempts{}; attempts < usize(1000000); ++attempts) {
    if (!writing && !data.is_empty()) {
      rstd_try(from.start_write(data.clone()));
      writing = true;
    }
    if (writing) {
      auto count = rstd_try(from.write());
      if (count) {
        data.advance(*count);
        writing = false;
      }
    }
    rstd_try(pump(from, to));
    rstd_try(pump(to, from));
    auto plain = rstd_try(to.read(usize(5)));
    if (plain)
      received.put_slice(plain->as_slice());
    if (received.len() == expected && data.is_empty() && !writing)
      return Ok(received.freeze());
  }
  return Err(Error::Protocol("memory TLS transfer stalled"_Str));
}
} // namespace
TEST(TlsSession, TinyBuffersCompleteTls12AndTls13AndBothDirections) {
  for (auto version : array<Version, 2>{Version::Tls12, Version::Tls13}) {
    Parameters a, b;
    a.minimum = a.maximum = b.minimum = b.maximum = version;
    a.bio_capacity = b.bio_capacity = usize(64);
    auto client_context = Context::client(test_trust(), rstd::move(a)).unwrap();
    auto identity = test_identity();
    auto server_context = Context::server(identity, rstd::move(b)).unwrap();
    auto client = Session::client(client_context,
                                  ServerName::dns("localhost"_str).unwrap())
                      .unwrap();
    auto server = Session::server(server_context).unwrap();
    EXPECT_TRUE(client.application_protocol().is_err());
    auto ready = negotiate(client, server);
    ASSERT_TRUE(ready.is_ok());
    EXPECT_EQ(client.negotiated_version().unwrap(), version);
    auto payload = Vec<u8>::with_capacity(usize(32769));
    for (usize i{}; i < usize(32769); ++i)
      payload.push(u8(i.to_primitive() & 255));
    auto received =
        transfer(client, server, Bytes::copy_from_slice(payload.as_slice()));
    ASSERT_TRUE(received.is_ok());
    EXPECT_EQ(received->as_slice(), payload.as_slice());
    EXPECT_EQ(transfer(server, client, Bytes::copy_from_slice("reply"_bytes))
                  .unwrap()
                  .as_slice(),
              "reply"_bytes);
    bool closed = false;
    for (usize i{}; i < usize(10000); ++i) {
      auto ac = client.shutdown();
      auto bc = server.shutdown();
      ASSERT_TRUE(ac.is_ok());
      ASSERT_TRUE(bc.is_ok());
      ASSERT_TRUE(pump(client, server).is_ok());
      ASSERT_TRUE(pump(server, client).is_ok());
      if (*ac && *bc && client.progress().pending_output == usize() &&
          server.progress().pending_output == usize()) {
        closed = true;
        break;
      }
    }
    ASSERT_TRUE(closed);
    auto eof = client.read(usize(1));
    ASSERT_TRUE(eof.is_ok());
    ASSERT_TRUE(eof->is_some());
    EXPECT_TRUE((**eof).is_empty());
  }
}
TEST(TlsSession, IpSanAndOwnedContextLifetime) {
  auto identity = test_identity();
  auto server_context = Context::server(identity).unwrap();
  auto server = Session::server(server_context).unwrap();
  auto client = [] {
    auto context = Context::client(test_trust()).unwrap();
    return Session::client(context,
                           ServerName::ip(rstd::net::Ipv4Addr::loopback()))
        .unwrap();
  }();
  EXPECT_TRUE(negotiate(client, server).is_ok());
}
TEST(TlsSession, RejectsUnknownCaWrongNameAndExpiredCertificate) {
  for (unsigned scenario = 0; scenario < 3; ++scenario) {
    auto trust = test_trust();
    if (scenario == 0)
      trust.ca_pem.clear();
    auto context = Context::client(rstd::move(trust)).unwrap();
    auto identity = test_identity(scenario == 2);
    auto server_context = Context::server(identity).unwrap();
    auto client =
        Session::client(context,
                        ServerName::dns(scenario == 1 ? "wrong.example"_str
                                                      : "localhost"_str)
                            .unwrap())
            .unwrap();
    auto server = Session::server(server_context).unwrap();
    auto result = negotiate(client, server);
    ASSERT_TRUE(result.is_err());
    EXPECT_TRUE(result.unwrap_err().is_Verification());
    EXPECT_TRUE(client.read(usize(1)).is_err());
  }
}
TEST(TlsSession, AlpnIsNegotiatedAndRequired) {
  Parameters a, b;
  a.application_protocols.push("dot"_Str);
  b.application_protocols.push("dot"_Str);
  a.require_application_protocol = b.require_application_protocol = true;
  auto context = Context::client(test_trust(), rstd::move(a)).unwrap();
  auto identity = test_identity();
  auto server_context = Context::server(identity, rstd::move(b)).unwrap();
  auto client =
      Session::client(context, ServerName::dns("localhost"_str).unwrap())
          .unwrap();
  auto server = Session::server(server_context).unwrap();
  ASSERT_TRUE(negotiate(client, server).is_ok());
  EXPECT_EQ(client.application_protocol().unwrap().as_slice(), "dot"_bytes);
  EXPECT_EQ(server.application_protocol().unwrap().as_slice(), "dot"_bytes);
}
TEST(TlsSession, MissingRequiredAlpnFails) {
  Parameters a;
  a.application_protocols.push("dot"_Str);
  a.require_application_protocol = true;
  auto context = Context::client(test_trust(), rstd::move(a)).unwrap();
  auto identity = test_identity();
  auto server_context = Context::server(identity).unwrap();
  auto client =
      Session::client(context, ServerName::dns("localhost"_str).unwrap())
          .unwrap();
  auto server = Session::server(server_context).unwrap();
  EXPECT_TRUE(negotiate(client, server).is_err());
}
TEST(TlsSession, UnexpectedTransportEofIsNotCloseNotify) {
  auto context = Context::client(test_trust()).unwrap();
  auto identity = test_identity();
  auto server_context = Context::server(identity).unwrap();
  auto client =
      Session::client(context, ServerName::dns("localhost"_str).unwrap())
          .unwrap();
  auto server = Session::server(server_context).unwrap();
  ASSERT_TRUE(negotiate(client, server).is_ok());
  ASSERT_TRUE(client.transport_eof().is_ok());
  auto result = client.read(usize(64));
  ASSERT_TRUE(result.is_err());
  EXPECT_TRUE(result.unwrap_err().is_UnexpectedEof());
}
TEST(TlsSession, ValidatesConfigurationAndIdentityBeforeIo) {
  EXPECT_TRUE(ServerName::dns(""_str).is_err());
  EXPECT_TRUE(ServerName::dns("local\0host"_str).is_err());
  EXPECT_TRUE(ServerName::dns("-bad.local"_str).is_err());
  EXPECT_TRUE(ServerName::dns("bad-.local"_str).is_err());
  Parameters parameters;
  parameters.bio_capacity = usize();
  EXPECT_TRUE(Context::client(test_trust(), rstd::move(parameters)).is_err());
  EXPECT_TRUE(Identity::from_pem(
                  Bytes::copy_from_slice(licrypto_test::certificate.as_bytes()),
                  Bytes::copy_from_slice(licrypto_test::other_key.as_bytes()))
                  .is_err());
}
TEST(TlsSession, RejectsCorruptCertificateAfterValidPem) {
  auto input = String::make(licrypto_test::certificate);
  input.push_str(
      "-----BEGIN CERTIFICATE-----\ninvalid!\n-----END CERTIFICATE-----\n"_str);
  EXPECT_TRUE(Identity::from_pem(
                  Bytes::copy_from_slice(input.as_str().as_bytes()),
                  Bytes::copy_from_slice(licrypto_test::private_key.as_bytes()))
                  .is_err());
  Trust trust;
  trust.use_system_roots = false;
  trust.ca_pem.push(Bytes::copy_from_slice(input.as_str().as_bytes()));
  EXPECT_TRUE(Context::client(rstd::move(trust)).is_err());
}
#endif
