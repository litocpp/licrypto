#include <rstd/test/gtest.hpp>
#if LITO_FEAT_OPENSSL
import licrypto;
import rstd;
#include "tls_material.hpp"
using namespace rstd;
using namespace rstd::prelude;
using namespace rstd::literals;
using bytes::Bytes;
using namespace licrypto;
using namespace licrypto::tls;
namespace {
auto trust() -> Trust {
  Trust value;
  value.use_system_roots = false;
  value.ca_pem.push(Bytes::copy_from_slice(licrypto_test::ca.as_bytes()));
  return value;
}
auto tcp_pair(async::Runtime &runtime)
    -> tuple<net::TcpStream, net::TcpStream> {
  auto listener =
      net::TcpListener::bind(net::SocketAddr::ipv4_loopback(u16())).unwrap();
  auto client =
      runtime.block_on(net::TcpStream::connect(listener.local_addr().unwrap()))
          .unwrap();
  auto accepted = runtime.block_on(listener.accept()).unwrap();
  runtime.block_on(rstd::move(listener).close()).unwrap();
  return {rstd::move(client), rstd::move(accepted.get<0>())};
}
auto pair(async::Runtime &runtime, usize capacity = usize(64),
          StreamOptions options = {}) -> tuple<Stream, Stream> {
  auto sockets = tcp_pair(runtime);
  auto pending = [&] {
    Parameters a, b;
    a.bio_capacity = b.bio_capacity = capacity;
    auto identity =
        Identity::from_pem(
            Bytes::copy_from_slice(licrypto_test::certificate.as_bytes()),
            Bytes::copy_from_slice(licrypto_test::private_key.as_bytes()))
            .unwrap();
    auto connector =
        Connector(Context::client(trust(), rstd::move(a)).unwrap(), options);
    auto acceptor =
        Acceptor(Context::server(identity, rstd::move(b)).unwrap(), options);
    return tuple{connector.connect(rstd::move(sockets.get<0>()),
                                   ServerName::dns("localhost"_str).unwrap()),
                 acceptor.accept(rstd::move(sockets.get<1>()))};
  }();
  auto ready =
      runtime
          .block_on(async::timeout(
              async::join(async::into_future(rstd::move(pending.get<0>())),
                          async::into_future(rstd::move(pending.get<1>()))),
              time::Duration::from_secs(u64(5))))
          .unwrap();
  EXPECT_TRUE(ready.get<0>().is_ok());
  EXPECT_TRUE(ready.get<1>().is_ok());
  return {rstd::move(ready.get<0>()).unwrap(),
          rstd::move(ready.get<1>()).unwrap()};
}
auto consume(const Stream &stream, usize count) -> async::coro<Bytes> {
  bytes::BytesMut out;
  while (out.len() < count) {
    auto data = (co_await stream.recv(usize(97))).unwrap();
    if (data.is_empty())
      break;
    out.put_slice(data.as_slice());
  }
  co_return out.freeze();
}
void close_pair(async::Runtime &runtime, tuple<Stream, Stream> streams) {
  auto closed =
      runtime
          .block_on(async::timeout(
              async::join(
                  async::into_future(rstd::move(streams.get<0>()).close()),
                  async::into_future(rstd::move(streams.get<1>()).close())),
              time::Duration::from_secs(u64(2))))
          .unwrap();
  EXPECT_TRUE(closed.get<0>().is_ok());
  EXPECT_TRUE(closed.get<1>().is_ok());
}
} // namespace
TEST(TlsStream, PendingReadDoesNotBlockWriteAndFactoriesOwnConfiguration) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto streams = pair(runtime);
  auto reading = streams.get<0>().recv();
  auto sent = runtime.block_on(
      streams.get<0>().send_all(Bytes::copy_from_slice("request"_bytes)));
  ASSERT_TRUE(sent.is_ok());
  EXPECT_EQ(*sent, usize(7));
  EXPECT_EQ(runtime.block_on(streams.get<1>().recv()).unwrap().as_slice(),
            "request"_bytes);
  EXPECT_TRUE(runtime
                  .block_on(streams.get<1>().send_all(
                      Bytes::copy_from_slice("reply"_bytes)))
                  .is_ok());
  EXPECT_EQ(runtime.block_on(rstd::move(reading)).unwrap().as_slice(),
            "reply"_bytes);
  close_pair(runtime, rstd::move(streams));
}
TEST(TlsStream, FullDuplexWithBoundedBuffersOnMultipleWorkers) {
  auto runtime = async::RuntimeBuilder::multi_thread()
                     .worker_threads(usize(2))
                     .enable_all()
                     .build()
                     .unwrap();
  StreamOptions options;
  options.maximum_buffered_plaintext = usize(127);
  auto streams = pair(runtime, usize(256), options);
  bytes::BytesMut bytes;
  bytes.resize(usize(131073), u8(19));
  auto payload = bytes.freeze();
  auto a = runtime.spawn(consume(streams.get<0>(), payload.len()));
  auto b = runtime.spawn(consume(streams.get<1>(), payload.len()));
  auto sent =
      runtime
          .block_on(async::timeout(
              async::join(async::into_future(
                              streams.get<0>().send_all(payload.clone())),
                          async::into_future(
                              streams.get<1>().send_all(payload.clone()))),
              time::Duration::from_secs(u64(5))))
          .unwrap();
  EXPECT_EQ(sent.get<0>().unwrap(), payload.len());
  EXPECT_EQ(sent.get<1>().unwrap(), payload.len());
  EXPECT_EQ(runtime.block_on(rstd::move(a)).unwrap().as_slice(),
            payload.as_slice());
  EXPECT_EQ(runtime.block_on(rstd::move(b)).unwrap().as_slice(),
            payload.as_slice());
  EXPECT_TRUE(runtime.block_on(streams.get<0>().flush()).is_ok());
  close_pair(runtime, rstd::move(streams));
}
TEST(TlsStream, ReadCancellationRetainsPublishedAndFutureInput) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto streams = pair(runtime);
  {
    auto abandoned = streams.get<0>().recv();
    EXPECT_TRUE(runtime
                    .block_on(async::timeout(
                        async::into_future(streams.get<0>().recv()),
                        time::Duration::from_millis(u64(10))))
                    .unwrap()
                    .unwrap_err()
                    .is_Busy());
    EXPECT_TRUE(runtime
                    .block_on(streams.get<1>().send_all(
                        Bytes::copy_from_slice("retained"_bytes)))
                    .is_ok());
    runtime.block_on(async::sleep(time::Duration::from_millis(u64(5))));
  }
  EXPECT_EQ(runtime.block_on(streams.get<0>().recv()).unwrap().as_slice(),
            "retained"_bytes);
  EXPECT_TRUE(
      runtime
          .block_on(async::timeout(async::into_future(streams.get<0>().recv()),
                                   time::Duration::from_millis(u64(2))))
          .is_err());
  EXPECT_TRUE(runtime
                  .block_on(streams.get<1>().send_all(
                      Bytes::copy_from_slice("next"_bytes)))
                  .is_ok());
  EXPECT_EQ(runtime.block_on(streams.get<0>().recv()).unwrap().as_slice(),
            "next"_bytes);
  close_pair(runtime, rstd::move(streams));
}
TEST(TlsStream, FuturesRetainConnectionAfterStreamDrop) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto pending = [&] {
    auto streams = pair(runtime);
    return tuple{
        streams.get<0>().recv(),
        streams.get<1>().send_all(Bytes::copy_from_slice("owned"_bytes)),
        rstd::move(streams.get<0>()).close(),
        rstd::move(streams.get<1>()).close()};
  }();
  auto io = async::join(async::into_future(rstd::move(pending.get<0>())),
                        async::into_future(rstd::move(pending.get<1>())));
  auto close = async::join(async::into_future(rstd::move(pending.get<2>())),
                           async::into_future(rstd::move(pending.get<3>())));
  auto result = runtime
                    .block_on(async::timeout(
                        async::join(rstd::move(io), rstd::move(close)),
                        time::Duration::from_secs(u64(2))))
                    .unwrap();
  EXPECT_EQ(result.get<0>().get<0>().unwrap().as_slice(), "owned"_bytes);
  EXPECT_EQ(result.get<0>().get<1>().unwrap(), usize(5));
  EXPECT_TRUE(result.get<1>().get<0>().is_ok());
  EXPECT_TRUE(result.get<1>().get<1>().is_ok());
}
TEST(TlsStream, HandshakeTimeoutClosesTransport) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto sockets = tcp_pair(runtime);
  StreamOptions options;
  options.handshake_timeout = time::Duration::from_millis(u64(5));
  auto connector = Connector(Context::client(trust()).unwrap(), options);
  auto result = runtime.block_on(connector.connect(
      rstd::move(sockets.get<0>()), ServerName::dns("localhost"_str).unwrap()));
  ASSERT_TRUE(result.is_err());
  EXPECT_TRUE(result.unwrap_err().is_Timeout());
  bytes::BytesMut received;
  while (true) {
    auto data = runtime.block_on(sockets.get<1>().recv()).unwrap();
    if (data.is_empty())
      break;
    received.put_slice(data.as_slice());
  }
  EXPECT_FALSE(received.is_empty());
  EXPECT_TRUE(runtime.block_on(rstd::move(sockets.get<1>()).close()).is_ok());
}
TEST(TlsStream, CloseTimeoutAndUnpolledReadCancellation) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  StreamOptions options;
  options.close_timeout = time::Duration::from_millis(u64(5));
  auto streams = pair(runtime, usize(64), options);
  {
    auto unpolled = streams.get<0>().recv();
  }
  EXPECT_TRUE(runtime
                  .block_on(streams.get<1>().send_all(
                      Bytes::copy_from_slice("later"_bytes)))
                  .is_ok());
  EXPECT_EQ(runtime.block_on(streams.get<0>().recv()).unwrap().as_slice(),
            "later"_bytes);
  auto result = runtime.block_on(rstd::move(streams.get<0>()).close());
  ASSERT_TRUE(result.is_err());
  EXPECT_TRUE(result.unwrap_err().is_Timeout());
}

TEST(TlsStream,
     PartialWriteCancellationKeepsAcceptedPrefixAndSubsequentWrites) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto streams = pair(runtime, usize(64));
  bytes::BytesMut payload;
  for (usize i{}; i < usize(8 * 1024 * 1024); ++i)
    payload.put_slice(array<u8, 1>{u8(i.to_primitive() % 251)}.as_slice());
  auto data = payload.freeze();
  {
    auto canceled = streams.get<0>().send_all(data.clone());
    runtime.block_on(async::sleep(time::Duration::from_millis(u64(5))));
  }
  auto receiving =
      runtime.spawn(consume(streams.get<1>(), data.len() + usize(4)));
  auto finish = [](const Stream &stream) -> async::coro<empty> {
    while (true) {
      auto flushed = co_await stream.flush();
      if (flushed.is_ok())
        break;
      EXPECT_TRUE(flushed.unwrap_err().is_Busy());
      co_await async::yield_now();
    }
    EXPECT_EQ((co_await stream.send_all(Bytes::copy_from_slice("done"_bytes)))
                  .unwrap(),
              usize(4));
    EXPECT_TRUE((co_await stream.flush()).is_ok());
    co_return empty{};
  };
  runtime
      .block_on(async::timeout(async::into_future(finish(streams.get<0>())),
                               time::Duration::from_secs(u64(5))))
      .unwrap();
  auto closing = runtime.spawn(rstd::move(streams.get<0>()).close());
  auto received =
      runtime
          .block_on(async::timeout(future::by_ref(receiving),
                                   time::Duration::from_secs(u64(5))))
          .unwrap()
          .unwrap();
  ASSERT_GE(received.len(), usize(4));
  auto count = received.len() - usize(4);
  EXPECT_GT(count, usize());
  EXPECT_LT(count, data.len());
  EXPECT_EQ(received.slice(usize(), count).as_slice(),
            data.slice(usize(), count).as_slice());
  EXPECT_EQ(received.slice(count, received.len()).as_slice(), "done"_bytes);
  EXPECT_TRUE(runtime.block_on(rstd::move(streams.get<1>()).close()).is_ok());
  EXPECT_TRUE(runtime.block_on(rstd::move(closing)).unwrap().is_ok());
}
TEST(TlsStream, CancelHandshakeAndCloseThenShutdownRuntime) {
  auto runtime = async::RuntimeBuilder::multi_thread()
                     .worker_threads(usize(2))
                     .enable_all()
                     .build()
                     .unwrap();
  {
    auto sockets = tcp_pair(runtime);
    auto connector = Connector(Context::client(trust()).unwrap());
    auto pending = connector.connect(rstd::move(sockets.get<0>()),
                                     ServerName::dns("localhost"_str).unwrap());
    EXPECT_TRUE(
        runtime
            .block_on(async::timeout(async::into_future(rstd::move(pending)),
                                     time::Duration::from_millis(u64(2))))
            .is_err());
    EXPECT_TRUE(runtime.block_on(rstd::move(sockets.get<1>()).close()).is_ok());
  }
  auto streams = pair(runtime);
  auto pending = streams.get<0>().recv();
  auto closing = rstd::move(streams.get<0>()).close();
  EXPECT_TRUE(
      runtime
          .block_on(async::timeout(async::into_future(rstd::move(closing)),
                                   time::Duration::from_millis(u64(2))))
          .is_err());
  EXPECT_TRUE(runtime.block_on(rstd::move(pending)).is_err());
}
TEST(TlsStream, CanceledFlushReleasesDirectionAndEmptySendCompletes) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto streams = pair(runtime);
  EXPECT_EQ(runtime.block_on(streams.get<0>().send(Bytes{})).unwrap(), usize());
  EXPECT_TRUE(runtime
                  .block_on(streams.get<0>().send_all(
                      Bytes::copy_from_slice("first"_bytes)))
                  .is_ok());
  {
    auto abandoned = streams.get<0>().flush();
  }
  auto sending = [](const Stream &stream) -> async::coro<empty> {
    while (true) {
      auto sent =
          co_await stream.send_all(Bytes::copy_from_slice("second"_bytes));
      if (sent.is_ok()) {
        EXPECT_EQ(*sent, usize(6));
        break;
      }
      EXPECT_TRUE(sent.unwrap_err().is_Busy());
      co_await async::yield_now();
    }
    co_return empty{};
  };
  runtime
      .block_on(async::timeout(async::into_future(sending(streams.get<0>())),
                               time::Duration::from_secs(u64(2))))
      .unwrap();
  EXPECT_EQ(runtime.block_on(consume(streams.get<1>(), usize(11))).as_slice(),
            "firstsecond"_bytes);
  close_pair(runtime, rstd::move(streams));
}
TEST(TlsStream, CloseConsumesUnreadPeerRecordsBeforeCloseNotify) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto streams = pair(runtime, usize(64));
  auto payload = Vec<u8>::make();
  payload.resize(usize(35000), u8(42));
  EXPECT_TRUE(runtime
                  .block_on(streams.get<1>().send_all(
                      Bytes::from_vec(rstd::move(payload))))
                  .is_ok());
  EXPECT_TRUE(runtime.block_on(streams.get<1>().flush()).is_ok());
  close_pair(runtime, rstd::move(streams));
}
TEST(TlsStream, CloseAfterFailedReadReportsTheCompletedResourceRelease) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto client = [&] {
    auto streams = pair(runtime);
    return rstd::move(streams.get<0>());
  }();
  auto read = runtime.block_on(client.recv());
  ASSERT_TRUE(read.is_err());
  EXPECT_TRUE(read.unwrap_err().is_UnexpectedEof());
  EXPECT_TRUE(runtime.block_on(rstd::move(client).close()).is_ok());
}
#endif
