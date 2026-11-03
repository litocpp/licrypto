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

struct TlsTransportFaults {
  bool armed{};
};
struct FragmentedTlsTransport {
  rstd::async::io::Stream stream;
  Option<sync::Arc<sync::Mutex<TlsTransportFaults>>> faults;
  auto send(Bytes input) const -> async::coro<rstd::io::Result<usize>> {
    if (faults && (*faults)->lock().unwrap()->armed) {
      co_await async::sleep(time::Duration::from_millis(u64(20)));
      co_return Err(rstd::io::Error::from_raw_os_error(i32(32)));
    }
    auto count = input.len() < usize(13) ? input.len() : usize(13);
    co_return co_await stream.send(input.slice(usize(), count));
  }
};
template <>
struct rstd::Impl<rstd::async::io::CompletionStream, FragmentedTlsTransport>
    : rstd::ImplBase<FragmentedTlsTransport> {
  auto recv_into(bytes::BytesMut buffer) const
      -> async::coro<async::io::StreamReceive> {
    return self().stream.recv_into(rstd::move(buffer));
  }
  auto send(Bytes input) const -> async::coro<rstd::io::Result<usize>> {
    return self().send(rstd::move(input));
  }
  auto flush() const -> async::coro<rstd::io::Result<empty>> {
    return self().stream.flush();
  }
  auto shutdown_write() const -> async::coro<rstd::io::Result<empty>> {
    return self().stream.shutdown_write();
  }
  void request_stop() const { self().stream.request_stop(); }
  auto wait_closed() const -> async::coro<rstd::io::Result<empty>> {
    return self().stream.wait_closed();
  }
  auto take_close_result() const -> Option<rstd::io::Result<empty>> {
    auto result = self().stream.take_close_result();
    if (result.is_some() && result->is_ok() && self().faults &&
        (*self().faults)->lock().unwrap()->armed)
      return Some(rstd::io::Result<empty>(
          Err(rstd::io::Error::from_raw_os_error(i32(5)))));
    return result;
  }
};
namespace {
auto fragmented(net::TcpStream transport,
                Option<sync::Arc<sync::Mutex<TlsTransportFaults>>> faults = {})
    -> rstd::async::io::Stream {
  auto backend = sync::Arc<rstd::dyn<async::io::CompletionStream>>::make(
      FragmentedTlsTransport{net::as_stream(rstd::move(transport)).unwrap(),
                             rstd::move(faults)});
  return async::io::Stream(rstd::move(backend));
}
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
          StreamOptions options = {}, Version version = Version::Tls13,
          bool completion_transport = false,
          Option<sync::Arc<sync::Mutex<TlsTransportFaults>>> faults = {})
    -> tuple<Stream, Stream> {
  auto sockets = tcp_pair(runtime);
  auto pending = [&] {
    Parameters a, b;
    a.minimum = a.maximum = b.minimum = b.maximum = version;
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
    if (completion_transport || faults)
      return tuple{connector.connect(fragmented(rstd::move(sockets.get<0>()),
                                                rstd::move(faults)),
                                     ServerName::dns("localhost"_str).unwrap()),
                   acceptor.accept(fragmented(rstd::move(sockets.get<1>())))};
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
TEST(TlsStream, CompletionTransportHandlesPartialWritesAndCloseBarrier) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto streams = pair(runtime, usize(64), {}, Version::Tls13, true);
  EXPECT_EQ(runtime
                .block_on(streams.get<0>().send_all(
                    Bytes::copy_from_slice("logical stream request"_bytes)))
                .unwrap(),
            usize(22));
  EXPECT_EQ(runtime.block_on(consume(streams.get<1>(), usize(22))).as_slice(),
            "logical stream request"_bytes);
  EXPECT_EQ(runtime
                .block_on(streams.get<1>().send_all(
                    Bytes::copy_from_slice("logical stream reply"_bytes)))
                .unwrap(),
            usize(20));
  EXPECT_EQ(runtime.block_on(consume(streams.get<0>(), usize(20))).as_slice(),
            "logical stream reply"_bytes);
  close_pair(runtime, rstd::move(streams));
}
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

TEST(TlsStream, SendOnlyCloseFlushesAlertWithoutPeerReply) {
  for (auto version : array<Version, 2>{Version::Tls12, Version::Tls13}) {
    auto runtime =
        async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
    auto streams = pair(runtime, usize(7), {}, version);
    auto pending = streams.get<0>().recv();
    auto result = runtime.block_on(async::timeout(
        async::into_future(
            rstd::move(streams.get<0>()).close(CloseMode::SendOnly)),
        time::Duration::from_millis(u64(100))));
    ASSERT_TRUE(result.is_ok());
    EXPECT_TRUE(result.unwrap().is_ok());
    EXPECT_TRUE(runtime.block_on(rstd::move(pending)).is_err());
    auto eof = runtime.block_on(streams.get<1>().recv());
    ASSERT_TRUE(eof.is_ok());
    EXPECT_TRUE(eof->is_empty());
    (void)runtime.block_on(rstd::move(streams.get<1>()).close());
  }
}

TEST(TlsStream, WaitPeerCloseFlushesPartialAlertsInBothDirections) {
  for (auto version : array<Version, 2>{Version::Tls12, Version::Tls13}) {
    auto runtime =
        async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
    close_pair(runtime, pair(runtime, usize(7), {}, version));
  }
}

TEST(TlsStream, SendOnlyClosePreservesPendingWriteBeforeAlert) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto streams = pair(runtime, usize(64));
  auto payload = Vec<u8>::make();
  payload.resize(usize(65537), u8(42));
  auto data = Bytes::from_vec(rstd::move(payload));
  auto sending = streams.get<0>().send_all(data.clone());
  auto closing = rstd::move(streams.get<0>()).close(CloseMode::SendOnly);
  auto read = runtime.spawn(consume(streams.get<1>(), data.len()));
  auto result = runtime
                    .block_on(async::timeout(
                        async::join(async::into_future(rstd::move(sending)),
                                    async::into_future(rstd::move(closing))),
                        time::Duration::from_secs(u64(2))))
                    .unwrap();
  EXPECT_EQ(result.get<0>().unwrap(), data.len());
  EXPECT_TRUE(result.get<1>().is_ok());
  EXPECT_EQ(runtime.block_on(rstd::move(read)).unwrap().as_slice(),
            data.as_slice());
  auto eof = runtime.block_on(streams.get<1>().recv());
  ASSERT_TRUE(eof.is_ok());
  EXPECT_TRUE(eof->is_empty());
  (void)runtime.block_on(rstd::move(streams.get<1>()).close());
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
TEST(TlsStream,
     FlushOwnsWriteFailureAndCancellationRetainsItAlongsideCloseFailure) {
  for (bool cancel : array<bool, 2>{false, true}) {
    auto runtime =
        async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
    auto faults =
        sync::Arc<sync::Mutex<TlsTransportFaults>>::make(TlsTransportFaults{});
    auto streams = pair(runtime, usize(4096), {}, Version::Tls13, true,
                        Some(faults.clone()));
    faults->lock().unwrap()->armed = true;
    auto &client = streams.get<0>();
    EXPECT_TRUE(
        runtime.block_on(client.send(Bytes::copy_from_slice("payload"_bytes)))
            .is_ok());
    auto reading = client.recv().into_future();
    if (cancel) {
      auto waiting = runtime.block_on(async::timeout(
          client.flush().into_future(), time::Duration::from_millis(u64(1))));
      EXPECT_TRUE(waiting.is_err());
    } else {
      auto failed = runtime.block_on(client.flush());
      ASSERT_TRUE(failed.is_err());
      ASSERT_TRUE(failed.as_ref().unwrap_err().is_Io());
      EXPECT_EQ(failed.as_ref().unwrap_err().as_Io().cause.raw_os_error(),
                Some(i32(32)));
    }
    auto read = runtime.block_on(rstd::move(reading));
    ASSERT_TRUE(read.is_err());
    EXPECT_TRUE(read.as_ref().unwrap_err().is_Closed());
    auto retained = client.take_error();
    EXPECT_EQ(retained.is_some(), cancel);
    if (retained.is_some()) {
      ASSERT_TRUE(retained->is_Io());
      EXPECT_EQ(retained->as_Io().cause.raw_os_error(), Some(i32(32)));
    }
    EXPECT_TRUE(client.take_error().is_none());
    auto closed = runtime.block_on(client.close());
    ASSERT_TRUE(closed.is_err());
    ASSERT_TRUE(closed.as_ref().unwrap_err().is_Io());
    EXPECT_EQ(closed.as_ref().unwrap_err().as_Io().cause.raw_os_error(),
              Some(i32(5)));
    EXPECT_TRUE(client.take_close_error().is_none());
    EXPECT_TRUE(
        runtime.block_on(client.close()).unwrap_err().is_InvalidState());
    (void)runtime.block_on(streams.get<1>().close(CloseMode::SendOnly));
  }
}
TEST(TlsStream, FailedHandshakeRetainsIndependentTransportCleanupFailure) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto sockets = tcp_pair(runtime);
  auto faults = sync::Arc<sync::Mutex<TlsTransportFaults>>::make(
      TlsTransportFaults{true});
  Connector connector(Context::client(trust()).unwrap());
  auto result = runtime.block_on(connector.connect(
      fragmented(rstd::move(sockets.get<0>()), Some(faults.clone())),
      ServerName::dns("localhost"_str).unwrap()));
  ASSERT_TRUE(result.is_err());
  auto error = rstd::move(result).unwrap_err();
  ASSERT_TRUE(error.is_Multiple());
  auto &errors = error.as_Multiple().errors;
  ASSERT_EQ(errors.len(), usize(2));
  ASSERT_TRUE(errors[usize()].is_Io());
  EXPECT_EQ(errors[usize()].as_Io().cause.raw_os_error(), Some(i32(32)));
  ASSERT_TRUE(errors[usize(1)].is_Io());
  EXPECT_EQ(errors[usize(1)].as_Io().cause.raw_os_error(), Some(i32(5)));
  EXPECT_TRUE(runtime.block_on(rstd::move(sockets.get<1>()).close()).is_ok());
}
TEST(TlsStream, CanceledReadDoesNotConsumeTerminalError) {
  auto runtime =
      async::RuntimeBuilder::current_thread().enable_all().build().unwrap();
  auto client = [&] {
    auto streams = pair(runtime);
    return rstd::move(streams.get<0>());
  }();
  {
    auto canceled = client.recv();
  }
  auto first = runtime.block_on(client.recv());
  ASSERT_TRUE(first.is_err());
  EXPECT_TRUE(first.unwrap_err().is_UnexpectedEof());
  auto second = runtime.block_on(client.recv());
  ASSERT_TRUE(second.is_err());
  EXPECT_TRUE(second.unwrap_err().is_Closed());
  EXPECT_TRUE(client.take_error().is_none());
  EXPECT_TRUE(runtime.block_on(client.close()).is_ok());
  auto repeated = runtime.block_on(client.close());
  ASSERT_TRUE(repeated.is_err());
  EXPECT_TRUE(repeated.unwrap_err().is_InvalidState());
}
#endif
