#![allow(unused)]

use async_trait::async_trait;
use dyn_clone::DynClone;
use std::{fmt::Debug, net::IpAddr};

use super::dns_socket::DnsSocket;

#[derive(thiserror::Error, Debug)]
pub enum CustomHandlerError {
    #[error(transparent)]
    IO(#[from] super::dns_socket::RequestError),

    #[error("Query is not processed by handler. Fallback to ICANN.")]
    Unhandled,
}

/**
 * Trait to implement to make AnyDns use a custom handler.
 * Important: Handler must be clonable so it can be used by multiple threads.
 */
#[async_trait]
pub trait CustomHandler: DynClone + Send + Sync {
    async fn lookup(
        &mut self,
        query: &Vec<u8>,
        socket: DnsSocket,
        from: Option<IpAddr>
    ) -> Result<Vec<u8>, CustomHandlerError>;
}

/**
 * Clonable handler holder
 */
pub struct HandlerHolder {
    pub func: Box<dyn CustomHandler>,
}

impl Clone for HandlerHolder {
    fn clone(&self) -> Self {
        Self {
            func: dyn_clone::clone_box(&*self.func),
        }
    }
}

impl Debug for HandlerHolder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandlerHolder")
            .field("func", &"HandlerHolder")
            .finish()
    }
}

impl HandlerHolder {
    /**
     * Bootstrap a holder from a struct that implements the CustomHandler.
     */
    pub fn new(f: impl CustomHandler + 'static) -> Self {
        HandlerHolder { func: Box::new(f) }
    }

    pub async fn call(
        &mut self,
        query: &Vec<u8>,
        socket: DnsSocket,
        from: Option<IpAddr>
    ) -> Result<Vec<u8>, CustomHandlerError> {
        self.func.lookup(query, socket, from).await
    }
}

#[derive(Clone)]
pub struct EmptyHandler {}

impl EmptyHandler {
    pub fn new() -> Self {
        EmptyHandler {}
    }
}

#[async_trait]
impl CustomHandler for EmptyHandler {
    async fn lookup(
        &mut self,
        _query: &Vec<u8>,
        _socket: DnsSocket,
        from: Option<IpAddr>
    ) -> Result<Vec<u8>, CustomHandlerError> {
        Err(CustomHandlerError::Unhandled)
    }
}

#[cfg(test)]
mod tests {
    use super::super::dns_socket::DnsSocket;
    use async_trait::async_trait;
    use std::net::{IpAddr, SocketAddr};

    use super::{CustomHandler, CustomHandlerError, HandlerHolder};

    struct ClonableStruct {
        value: String,
    }

    impl Clone for ClonableStruct {
        fn clone(&self) -> Self {
            Self {
                value: format!("{} cloned", self.value.clone()),
            }
        }
    }

    #[derive(Clone)]
    pub struct TestHandler {
        value: ClonableStruct,
    }

    impl TestHandler {
        pub fn new(value: &str) -> Self {
            TestHandler {
                value: ClonableStruct {
                    value: value.to_string(),
                },
            }
        }
    }
    #[async_trait]
    impl CustomHandler for TestHandler {
        async fn lookup(
            &mut self,
            _query: &Vec<u8>,
            _socket: DnsSocket,
            from: Option<IpAddr>
        ) -> Result<Vec<u8>, CustomHandlerError> {
            println!("value {}", self.value.value);
            Err(CustomHandlerError::Unhandled)
        }
    }

    #[tokio::test]
    async fn run_processor() {
        let test1 = TestHandler::new("test1");
        let holder1 = HandlerHolder::new(test1);
        let mut cloned = holder1.clone();
        let icann_fallback: SocketAddr = "8.8.8.8:53".parse().unwrap();

        let socket = DnsSocket::new(
            "0.0.0.0:18293".parse().unwrap(),
            icann_fallback,
            holder1.clone(),
            None
        )
        .await
        .unwrap();
        let result = cloned.call(&vec![], socket, None).await;
        assert!(result.is_err());
    }
}
