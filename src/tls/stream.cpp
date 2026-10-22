module;
#include <rstd/macro.hpp>
module licrypto;
import :tls.stream;
import rstd;
using namespace rstd::prelude;
using namespace rstd::literals;
using rstd::bytes::Bytes;
using rstd::sync::Arc;
namespace licrypto::tls {

template <class T, class Input = empty> struct Request {
  using Value = T;
  struct Reply {
    Option<CryptoResult<T>> result;
    Option<rstd::task::Waker> waker;
    bool canceled = false;
    bool consumed = false;
  };
  Input input;
  rstd::sync::Mutex<Reply> reply;
  explicit Request(Input input = {})
      : input(rstd::move(input)), reply(Reply{}) {}
  auto canceled() const -> bool {
    auto state = reply.lock().unwrap();
    return state->canceled;
  }
  auto consumed() const -> bool {
    auto state = reply.lock().unwrap();
    return state->consumed;
  }
  void cancel() {
    auto state = reply.lock().unwrap();
    state->canceled = true;
    state->waker = None();
  }
  auto complete(CryptoResult<T> result) -> bool {
    Option<rstd::task::Waker> wake;
    {
      auto state = reply.lock().unwrap();
      if (state->canceled || state->consumed || state->result)
        return false;
      state->result = Some(rstd::move(result));
      wake = state->waker.take();
    }
    if (wake)
      rstd::move(*wake).wake();
    return true;
  }
  auto poll(rstd::task::Context &cx) -> rstd::task::Poll<CryptoResult<T>> {
    auto state = reply.lock().unwrap();
    if (state->result) {
      state->consumed = true;
      return rstd::task::Poll<CryptoResult<T>>::Ready(
          rstd::move(state->result.take()).unwrap());
    }
    state->waker = Some(cx.waker().clone());
    return rstd::task::Poll<CryptoResult<T>>::Pending();
  }
};
struct ReadInput {
  usize maximum;
};
struct WriteInput {
  Bytes data;
  bool all;
  usize accepted{};
  bool started = false;
};
using ReadRequest = Request<Bytes, ReadInput>;
using WriteRequest = Request<usize, WriteInput>;
using SimpleRequest = Request<empty>;
struct Commands {
  Option<Arc<ReadRequest>> read;
  Option<Arc<WriteRequest>> write;
  Option<Arc<SimpleRequest>> flush;
  Option<Arc<SimpleRequest>> close;
  Arc<SimpleRequest> handshake;
  Option<rstd::task::Waker> driver_waker;
  Option<Error> error;
  Option<Error> close_error;
  Bytes protocol;
  Version version = Version::Tls12;
  bool ready = false;
  bool closing = false;
  bool abort = false;
  bool closed = false;
  explicit Commands(Arc<SimpleRequest> handshake)
      : handshake(rstd::move(handshake)) {}
};
struct SharedConnection {
  rstd::sync::Mutex<Commands> commands;
  explicit SharedConnection(Arc<SimpleRequest> handshake)
      : commands(Commands(rstd::move(handshake))) {}
  void wake_driver() const {
    Option<rstd::task::Waker> wake;
    {
      auto state = commands.lock().unwrap();
      if (state->driver_waker)
        wake = Some(state->driver_waker->clone());
    }
    if (wake)
      rstd::move(*wake).wake();
  }
};
struct ConnectionOwner {
  Arc<SharedConnection> shared;
  rstd::async::AbortOnDropHandle<empty> driver;
  ConnectionOwner(Arc<SharedConnection> shared,
                  rstd::async::JoinHandle<empty> driver)
      : shared(rstd::move(shared)), driver(rstd::move(driver)) {}
};

template <class R> class WaitRequest {
  Arc<ConnectionOwner> owner_;
  Arc<R> request_;
  bool active_ = true;
  bool abort_on_cancel_;

public:
  using Output = CryptoResult<typename R::Value>;
  WaitRequest(Arc<ConnectionOwner> owner, Arc<R> request,
              bool abort_on_cancel = false)
      : owner_(rstd::move(owner)), request_(rstd::move(request)),
        abort_on_cancel_(abort_on_cancel) {}
  WaitRequest(const WaitRequest &) = delete;
  auto operator=(const WaitRequest &) -> WaitRequest & = delete;
  WaitRequest(WaitRequest &&other) noexcept
      : owner_(rstd::move(other.owner_)), request_(rstd::move(other.request_)),
        active_(rstd::exchange(other.active_, false)),
        abort_on_cancel_(other.abort_on_cancel_) {}
  ~WaitRequest() {
    if (!active_)
      return;
    request_->cancel();
    if (abort_on_cancel_) {
      auto state = owner_->shared->commands.lock().unwrap();
      state->abort = true;
    }
    owner_->shared->wake_driver();
  }
  auto poll(mut_ref<WaitRequest> self, rstd::task::Context &cx)
      -> rstd::task::Poll<Output> {
    auto out = self->request_->poll(cx);
    if (out.is_ready()) {
      self->active_ = false;
      self->owner_->shared->wake_driver();
    }
    return out;
  }
};
template <class R>
auto await_request(WaitRequest<R> request)
    -> rstd::async::coro<CryptoResult<typename R::Value>> {
  co_return co_await rstd::move(request);
}
template <class T>
auto ready_result(CryptoResult<T> result)
    -> rstd::async::coro<CryptoResult<T>> {
  co_return rstd::move(result);
}

class ConnectionDriver {
  using Receive = rstd::async::coro<rstd::io::Result<Bytes>>::Future;
  using Send = rstd::async::coro<rstd::io::Result<usize>>::Future;
  using Close = rstd::async::coro<rstd::io::Result<empty>>::Future;
  Arc<SharedConnection> shared_;
  rstd::net::TcpStream transport_;
  Session session_;
  StreamOptions options_;
  Option<Receive> receiving_;
  Option<Send> sending_;
  Option<Close> closing_transport_;
  Option<rstd::async::Sleep> deadline_;
  Option<Error> error_;
  Bytes input_;
  Bytes output_;
  Option<Bytes> plaintext_;
  Option<Arc<ReadRequest>> delivery_;
  usize delivered_{};
  bool ready_ = false;
  bool closing_ = false;
  bool tls_closed_ = false;
  bool transport_eof_ = false;
  bool peer_eof_ = false;

  void fail(Error error) {
    if (!error_)
      error_ = Some(rstd::move(error));
  }
  void begin_transport_close() {
    if (closing_transport_)
      return;
    receiving_ = None();
    sending_ = None();
    closing_transport_ = Some(rstd::move(transport_).close().into_future());
  }
  auto finish(rstd::io::Result<empty> closed) -> rstd::task::Poll<empty> {
    Option<Error> close_error;
    if (closed.is_err()) {
      close_error = Some(Error::Io(rstd::move(closed).unwrap_err()));
      if (!error_)
        fail(close_error->clone());
    } else if (closing_ && error_) {
      close_error = Some(error_->clone());
    }
    Option<Arc<ReadRequest>> read;
    Option<Arc<WriteRequest>> write;
    Option<Arc<SimpleRequest>> flush, close;
    Arc<SimpleRequest> handshake = [&] {
      auto state = shared_->commands.lock().unwrap();
      return state->handshake.clone();
    }();
    {
      auto state = shared_->commands.lock().unwrap();
      state->closed = true;
      if (error_)
        state->error = Some(error_->clone());
      if (close_error)
        state->close_error = Some(close_error->clone());
      state->driver_waker = None();
      read = state->read.take();
      write = state->write.take();
      flush = state->flush.take();
      close = state->close.take();
    }
    handshake->complete(Err(error_ ? error_->clone() : Error::Closed()));
    if (read)
      (*read)->complete(Err(error_ ? error_->clone() : Error::Closed()));
    if (write)
      (*write)->complete(Err(error_ ? error_->clone() : Error::Closed()));
    if (flush)
      (*flush)->complete(Err(error_ ? error_->clone() : Error::Closed()));
    if (close)
      (*close)->complete(close_error
                             ? CryptoResult<empty>(Err(close_error->clone()))
                             : CryptoResult<empty>(Ok(empty{})));
    return rstd::task::Poll<empty>::Ready(empty{});
  }
  void clear_read(const Arc<ReadRequest> &request) {
    auto state = shared_->commands.lock().unwrap();
    if (state->read && (*state->read).as_ptr() == request.as_ptr())
      state->read = None();
  }
  auto consume_delivery() -> bool {
    if (!delivery_)
      return false;
    if (!(*delivery_)->consumed() && !(*delivery_)->canceled())
      return false;
    if ((*delivery_)->consumed()) {
      if (plaintext_ && delivered_ < plaintext_->len())
        plaintext_->advance(delivered_);
      else
        plaintext_ = None();
    }
    clear_read(*delivery_);
    delivery_ = None();
    return true;
  }
  auto same_progress(const Progress &a, const Progress &b) const -> bool {
    return a.ready == b.ready && a.peer_closed == b.peer_closed &&
           a.local_closed == b.local_closed && a.needs_input == b.needs_input &&
           a.pending_output == b.pending_output &&
           a.input_capacity == b.input_capacity;
  }
  auto advance(rstd::task::Context &cx) -> rstd::task::Poll<empty> {
    for (unsigned budget = 0; budget < 64; ++budget) {
      bool changed = false;
      bool abort = false;
      {
        auto state = shared_->commands.lock().unwrap();
        state->driver_waker = Some(cx.waker().clone());
        abort = state->abort;
        if (state->closing && !closing_) {
          closing_ = true;
          deadline_ = Some(rstd::async::sleep(options_.close_timeout));
        }
      }
      if (abort)
        fail(Error::Closed());
      if (deadline_) {
        auto timed = rstd::future::poll(*deadline_, cx);
        if (timed.is_ready()) {
          deadline_ = None();
          fail(Error::Timeout());
        }
      }
      if (error_)
        begin_transport_close();
      if (closing_transport_) {
        auto out = rstd::future::poll(*closing_transport_, cx);
        if (out.is_pending())
          return rstd::task::Poll<empty>::Pending();
        return finish(rstd::move(out).take());
      }
      if (receiving_) {
        auto received = rstd::future::poll(*receiving_, cx);
        if (received.is_ready()) {
          receiving_ = None();
          changed = true;
          auto result = rstd::move(received).take();
          if (result.is_err())
            fail(Error::Io(rstd::move(result).unwrap_err()));
          else {
            input_ = rstd::move(result).unwrap();
            if (input_.is_empty()) {
              transport_eof_ = true;
              auto eof = session_.transport_eof();
              if (eof.is_err())
                fail(rstd::move(eof).unwrap_err());
            }
          }
        }
      }
      if (sending_) {
        auto sent = rstd::future::poll(*sending_, cx);
        if (sent.is_ready()) {
          sending_ = None();
          changed = true;
          auto result = rstd::move(sent).take();
          if (result.is_err())
            fail(Error::Io(rstd::move(result).unwrap_err()));
          else if (*result == usize() || *result > output_.len())
            fail(Error::Io(rstd::io::Error::from_kind(
                rstd::io::ErrorKind{rstd::io::ErrorKind::WriteZero})));
          else
            output_.advance(*result);
        }
      }
      if (error_)
        continue;
      if (!input_.is_empty()) {
        auto fed = session_.feed(input_.as_slice());
        if (fed.is_err()) {
          fail(rstd::move(fed).unwrap_err());
          continue;
        }
        if (*fed != usize()) {
          input_.advance(*fed);
          changed = true;
        }
      }
      auto before = session_.progress();
      if (!ready_) {
        auto handshake = session_.handshake();
        if (handshake.is_err()) {
          fail(rstd::move(handshake).unwrap_err());
          continue;
        }
        if (*handshake && session_.progress().pending_output == usize() &&
            output_.is_empty() && !sending_) {
          auto protocol = session_.application_protocol();
          auto version = session_.negotiated_version();
          if (protocol.is_err()) {
            fail(rstd::move(protocol).unwrap_err());
            continue;
          }
          if (version.is_err()) {
            fail(rstd::move(version).unwrap_err());
            continue;
          }
          Arc<SimpleRequest> reply = [&] {
            auto state = shared_->commands.lock().unwrap();
            state->protocol = rstd::move(protocol).unwrap();
            state->version = *version;
            state->ready = true;
            return state->handshake.clone();
          }();
          ready_ = true;
          deadline_ = None();
          changed = true;
          reply->complete(Ok(empty{}));
        }
      } else {
        changed = consume_delivery() || changed;
        Option<Arc<ReadRequest>> read;
        Option<Arc<WriteRequest>> write;
        Option<Arc<SimpleRequest>> flush;
        {
          auto state = shared_->commands.lock().unwrap();
          if (state->read)
            read = Some((*state->read).clone());
          if (state->write)
            write = Some((*state->write).clone());
          if (state->flush)
            flush = Some((*state->flush).clone());
        }
        if (write) {
          auto &request = **write;
          auto &input = request.input;
          if (request.canceled() && !input.started) {
            auto state = shared_->commands.lock().unwrap();
            state->write = None();
            changed = true;
          } else {
            if (!input.started) {
              auto started = session_.start_write(input.data.clone());
              if (started.is_err()) {
                fail(rstd::move(started).unwrap_err());
                continue;
              }
              input.started = true;
              changed = true;
            }
            auto written = session_.write();
            if (written.is_err()) {
              fail(rstd::move(written).unwrap_err());
              continue;
            }
            if (written->is_some()) {
              auto count = **written;
              input.data.advance(count);
              input.accepted += count;
              input.started = false;
              changed = true;
              if (!input.all || input.data.is_empty() || request.canceled()) {
                {
                  auto state = shared_->commands.lock().unwrap();
                  state->write = None();
                }
                request.complete(Ok(input.accepted));
              }
            }
          }
        }
        if (read && !delivery_) {
          if ((*read)->canceled())
            clear_read(*read);
          else {
            if (!plaintext_) {
              if (peer_eof_)
                plaintext_ = Some(Bytes{});
              else {
                auto maximum =
                    (*read)->input.maximum < options_.maximum_buffered_plaintext
                        ? (*read)->input.maximum
                        : options_.maximum_buffered_plaintext;
                auto plain = session_.read(maximum);
                if (plain.is_err()) {
                  fail(rstd::move(plain).unwrap_err());
                  continue;
                }
                if (plain->is_some()) {
                  plaintext_ = Some(rstd::move(*plain).unwrap());
                  if (plaintext_->is_empty())
                    peer_eof_ = true;
                  changed = true;
                }
              }
            }
            if (plaintext_) {
              auto maximum = (*read)->input.maximum;
              auto count =
                  maximum < plaintext_->len() ? maximum : plaintext_->len();
              // Retain the original bytes until the application consumes the
              // reply.
              if ((*read)->complete(Ok(plaintext_->slice(usize(), count)))) {
                delivery_ = Some((*read).clone());
                delivered_ = count;
                changed = true;
              }
            }
          }
        }
        if (flush && (*flush)->canceled()) {
          {
            auto state = shared_->commands.lock().unwrap();
            state->flush = None();
          }
          flush = None();
          changed = true;
        }
        if (flush && !write && output_.is_empty() && !sending_ &&
            session_.progress().pending_output == usize()) {
          {
            auto state = shared_->commands.lock().unwrap();
            state->flush = None();
          }
          (*flush)->complete(Ok(empty{}));
          changed = true;
        }
        if (closing_ && !write) {
          auto progress = session_.progress();
          if (progress.local_closed && !progress.peer_closed) {
            // OpenSSL requires pending application records to be read before
            // completing the peer's close_notify exchange.
            auto trailing = session_.read(options_.maximum_buffered_plaintext);
            if (trailing.is_err()) {
              fail(rstd::move(trailing).unwrap_err());
              continue;
            }
            if (trailing->is_some())
              changed = true;
            progress = session_.progress();
          }
          if (!progress.local_closed || progress.peer_closed) {
            auto closed = session_.shutdown();
            if (closed.is_err()) {
              fail(rstd::move(closed).unwrap_err());
              continue;
            }
            tls_closed_ = *closed;
          }
        }
      }
      auto progress = session_.progress();
      changed = !same_progress(before, progress) || changed;
      if (output_.is_empty() && !sending_ &&
          progress.pending_output != usize()) {
        auto output = session_.drain();
        if (output.is_err()) {
          fail(rstd::move(output).unwrap_err());
          continue;
        }
        output_ = rstd::move(output).unwrap();
        changed = true;
      }
      if (!output_.is_empty() && !sending_) {
        sending_ = Some(transport_.send(output_.clone()).into_future());
        changed = true;
      }
      if (tls_closed_ && output_.is_empty() && !sending_ &&
          session_.progress().pending_output == usize()) {
        begin_transport_close();
        continue;
      }
      if (progress.needs_input && !transport_eof_ && !receiving_ &&
          input_.is_empty() && progress.input_capacity != usize()) {
        auto maximum = progress.input_capacity < usize(16384)
                           ? progress.input_capacity
                           : usize(16384);
        receiving_ = Some(transport_.recv(maximum).into_future());
        changed = true;
      }
      if (!changed)
        return rstd::task::Poll<empty>::Pending();
    }
    cx.waker().wake_by_ref();
    return rstd::task::Poll<empty>::Pending();
  }

public:
  using Output = empty;
  ConnectionDriver(Arc<SharedConnection> shared, rstd::net::TcpStream transport,
                   Session session, StreamOptions options)
      : shared_(rstd::move(shared)), transport_(rstd::move(transport)),
        session_(rstd::move(session)), options_(options),
        deadline_(Some(rstd::async::sleep(options.handshake_timeout))) {}
  ConnectionDriver(const ConnectionDriver &) = delete;
  auto operator=(const ConnectionDriver &) -> ConnectionDriver & = delete;
  ConnectionDriver(ConnectionDriver &&) noexcept = default;
  auto poll(mut_ref<ConnectionDriver> self, rstd::task::Context &cx)
      -> rstd::task::Poll<empty> {
    return self->advance(cx);
  }
};

Stream::Stream(Arc<ConnectionOwner> owner) : owner_(rstd::move(owner)) {}
Stream::Stream(Stream &&) noexcept = default;
auto Stream::operator=(Stream &&) noexcept -> Stream & = default;
Stream::~Stream() = default;

auto make_owner(rstd::net::TcpStream transport, Session session,
                StreamOptions options) -> Arc<ConnectionOwner> {
  auto handshake = Arc<SimpleRequest>::make();
  auto shared = Arc<SharedConnection>::make(handshake.clone());
  auto task = rstd::async::spawn(ConnectionDriver(
      shared.clone(), rstd::move(transport), rstd::move(session), options));
  return Arc<ConnectionOwner>::make(rstd::move(shared), rstd::move(task));
}
auto Connector::connect_owned(Context context, rstd::net::TcpStream transport,
                              ServerName name, StreamOptions options)
    -> rstd::async::coro<CryptoResult<Stream>> {
  if (options.maximum_buffered_plaintext == usize() ||
      options.maximum_buffered_plaintext > usize(1048576)) {
    (void)co_await rstd::move(transport).close();
    co_return Err(Error::Configuration("invalid plaintext buffer limit"_Str));
  }
  auto session = Session::client(context, rstd::move(name));
  if (session.is_err()) {
    (void)co_await rstd::move(transport).close();
    co_return Err(rstd::move(session).unwrap_err());
  }
  auto owner =
      make_owner(rstd::move(transport), rstd::move(session).unwrap(), options);
  auto reply = [&] {
    auto state = owner->shared->commands.lock().unwrap();
    return state->handshake.clone();
  }();
  auto ready = co_await WaitRequest<SimpleRequest>(owner.clone(),
                                                   rstd::move(reply), true);
  if (ready.is_err())
    co_return Err(rstd::move(ready).unwrap_err());
  co_return Ok(Stream(rstd::move(owner)));
}
auto Acceptor::accept_owned(Context context, rstd::net::TcpStream transport,
                            StreamOptions options)
    -> rstd::async::coro<CryptoResult<Stream>> {
  if (options.maximum_buffered_plaintext == usize() ||
      options.maximum_buffered_plaintext > usize(1048576)) {
    (void)co_await rstd::move(transport).close();
    co_return Err(Error::Configuration("invalid plaintext buffer limit"_Str));
  }
  auto session = Session::server(context);
  if (session.is_err()) {
    (void)co_await rstd::move(transport).close();
    co_return Err(rstd::move(session).unwrap_err());
  }
  auto owner =
      make_owner(rstd::move(transport), rstd::move(session).unwrap(), options);
  auto reply = [&] {
    auto state = owner->shared->commands.lock().unwrap();
    return state->handshake.clone();
  }();
  auto ready = co_await WaitRequest<SimpleRequest>(owner.clone(),
                                                   rstd::move(reply), true);
  if (ready.is_err())
    co_return Err(rstd::move(ready).unwrap_err());
  co_return Ok(Stream(rstd::move(owner)));
}
auto Connector::connect(rstd::net::TcpStream transport, ServerName peer) const
    -> rstd::async::coro<CryptoResult<Stream>> {
  return connect_owned(context_.clone(), rstd::move(transport),
                       rstd::move(peer), options_);
}
auto Acceptor::accept(rstd::net::TcpStream transport) const
    -> rstd::async::coro<CryptoResult<Stream>> {
  return accept_owned(context_.clone(), rstd::move(transport), options_);
}
auto Stream::recv(usize maximum_size) const
    -> rstd::async::coro<CryptoResult<Bytes>> {
  if (!owner_)
    return ready_result<Bytes>(Err(Error::Closed()));
  if (maximum_size == usize())
    return ready_result<Bytes>(Err(Error::Io(rstd::io::Error::from_kind(
        rstd::io::ErrorKind{rstd::io::ErrorKind::InvalidInput}))));
  auto request = Arc<ReadRequest>::make(ReadInput{maximum_size});
  {
    auto state = owner_->shared->commands.lock().unwrap();
    if (state->closed)
      return ready_result<Bytes>(
          Err(state->error ? state->error->clone() : Error::Closed()));
    if (state->closing)
      return ready_result<Bytes>(Err(Error::Closed()));
    if (state->read && !(*state->read)->canceled() &&
        !(*state->read)->consumed())
      return ready_result<Bytes>(Err(Error::Busy()));
    state->read = Some(request.clone());
  }
  owner_->shared->wake_driver();
  return await_request(
      WaitRequest<ReadRequest>(owner_.clone(), rstd::move(request)));
}
auto enqueue_write(Arc<ConnectionOwner> owner, Bytes input, bool all)
    -> rstd::async::coro<CryptoResult<usize>> {
  auto request = Arc<WriteRequest>::make(WriteInput{rstd::move(input), all});
  {
    auto state = owner->shared->commands.lock().unwrap();
    if (state->closed)
      return ready_result<usize>(
          Err(state->error ? state->error->clone() : Error::Closed()));
    if (state->closing)
      return ready_result<usize>(Err(Error::Closed()));
    if (state->write || state->flush)
      return ready_result<usize>(Err(Error::Busy()));
    state->write = Some(request.clone());
  }
  owner->shared->wake_driver();
  return await_request(
      WaitRequest<WriteRequest>(rstd::move(owner), rstd::move(request)));
}
auto Stream::send(Bytes input) const -> rstd::async::coro<CryptoResult<usize>> {
  if (!owner_)
    return ready_result<usize>(Err(Error::Closed()));
  return enqueue_write(owner_.clone(), rstd::move(input), false);
}
auto Stream::send_all(Bytes input) const
    -> rstd::async::coro<CryptoResult<usize>> {
  if (!owner_)
    return ready_result<usize>(Err(Error::Closed()));
  return enqueue_write(owner_.clone(), rstd::move(input), true);
}
auto Stream::flush() const -> rstd::async::coro<CryptoResult<empty>> {
  if (!owner_)
    return ready_result<empty>(Err(Error::Closed()));
  auto request = Arc<SimpleRequest>::make();
  {
    auto state = owner_->shared->commands.lock().unwrap();
    if (state->closed)
      return ready_result<empty>(
          Err(state->error ? state->error->clone() : Error::Closed()));
    if (state->closing)
      return ready_result<empty>(Err(Error::Closed()));
    if (state->write || state->flush)
      return ready_result<empty>(Err(Error::Busy()));
    state->flush = Some(request.clone());
  }
  owner_->shared->wake_driver();
  return await_request(
      WaitRequest<SimpleRequest>(owner_.clone(), rstd::move(request)));
}
auto Stream::close() && -> rstd::async::coro<CryptoResult<empty>> {
  if (!owner_)
    return ready_result<empty>(Err(Error::Closed()));
  auto owner = rstd::move(owner_);
  auto request = Arc<SimpleRequest>::make();
  {
    auto state = owner->shared->commands.lock().unwrap();
    if (state->closed)
      return ready_result<empty>(
          state->close_error
              ? CryptoResult<empty>(Err(state->close_error->clone()))
              : CryptoResult<empty>(Ok(empty{})));
    state->closing = true;
    state->close = Some(request.clone());
  }
  owner->shared->wake_driver();
  return await_request(
      WaitRequest<SimpleRequest>(rstd::move(owner), rstd::move(request), true));
}
auto Stream::application_protocol() const -> CryptoResult<Bytes> {
  if (!owner_)
    return Err(Error::Closed());
  auto state = owner_->shared->commands.lock().unwrap();
  if (!state->ready)
    return Err(Error::InvalidState("TLS metadata before handshake"_Str));
  return Ok(state->protocol.clone());
}
auto Stream::negotiated_version() const -> CryptoResult<Version> {
  if (!owner_)
    return Err(Error::Closed());
  auto state = owner_->shared->commands.lock().unwrap();
  if (!state->ready)
    return Err(Error::InvalidState("TLS metadata before handshake"_Str));
  return Ok(state->version);
}
} // namespace licrypto::tls
