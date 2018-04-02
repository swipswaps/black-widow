use std::marker::PhantomData;
use std::fmt::Debug;
use futures::prelude::*;
use futures::stream::once;


#[derive(Debug)]
pub struct VecStream<T: Debug, U: Debug> {
    _marker: PhantomData<U>,
    inner: Vec<T>,
    closed: bool,
    size: usize,
    read_pointer: usize,
    write_pointer: usize,
}

impl<T: Debug, U: Debug> VecStream<T, U> {
    pub fn new() -> VecStream<T, U> {
        VecStream::with_capacity(20)
    }

    pub fn with_capacity(capacity: usize) -> VecStream<T, U> {
        VecStream {
            inner: Vec::with_capacity(capacity),
            closed: false,
            size: 0,
            read_pointer: 0,
            write_pointer: 0,
            _marker: PhantomData,
        }
    }
}

impl<T: Debug, U: Debug> Sink for VecStream<T, U> {
    type SinkItem = T;
    type SinkError = U;

    fn start_send(&mut self, item: <Self as Sink>::SinkItem) -> Result<AsyncSink<<Self as Sink>::SinkItem>, <Self as Sink>::SinkError> {
        if self.size == self.inner.capacity() || self.closed {
            return Ok(AsyncSink::NotReady(item));
        }

        self.inner.insert(self.write_pointer, item);
        self.write_pointer = (self.write_pointer + 1) % self.inner.capacity();
        self.size = self.size + 1;

        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        if self.size == self.inner.capacity() || self.closed {
            return Ok(Async::NotReady);
        }

        Ok(Async::Ready(()))
    }

    fn close(&mut self) -> Result<Async<()>, <Self as Sink>::SinkError> {
        self.closed = false;

        Ok(Async::Ready(()))
    }
}

impl<T: Debug, U: Debug> Stream for VecStream<T, U> {
    type Item = T;
    type Error = U;

    fn poll(&mut self) -> Result<Async<Option<<Self as Stream>::Item>>, <Self as Stream>::Error> {
        if self.size == 0 {
            return Ok(Async::NotReady);
        }

        let item = self.inner.remove(self.read_pointer);
        self.read_pointer = (self.read_pointer + 1) % self.inner.capacity();
        self.size = self.size - 1;

        Ok(Async::Ready(Some(item)))
    }
}

#[test]
fn test_split() {
    let x: VecStream<u8, ()> = VecStream::with_capacity(4);

    let (mut sink, mut stream) = x.split();
    sink.start_send(1);
    assert_eq!(Ok(Async::Ready(Some(1))), stream.poll());
}