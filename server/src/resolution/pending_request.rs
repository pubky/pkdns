#![allow(unused)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::sync::oneshot;

/// A pending request to a forward server.
#[derive(Debug)]
pub struct PendingRequest {
    /// Where the request was sent to
    pub to: SocketAddr,
    /// When the request was sent
    pub sent_at: Instant,
    /// The original query id coming from the client
    pub original_query_id: u16,
    /// The forward query id sent to the forward server
    pub forward_query_id: u16,
    /// The sender to send the response back to the client
    pub tx: oneshot::Sender<Vec<u8>>,
}

#[derive(Debug, Clone, Hash, PartialEq)]
struct PendingRequestKey {
    to: SocketAddr,
    forward_query_id: u16,
}

impl Eq for PendingRequestKey {}

/**
 * Thread safe pending request store.
 * Use `.clone()` to give each thread one store struct.
 * The data will stay shared.
 */
#[derive(Debug, Clone)]
pub struct PendingRequestStore {
    pending: Arc<Mutex<HashMap<PendingRequestKey, PendingRequest>>>,
}

impl PendingRequestStore {
    /// Insert a new pending request
    pub fn insert(&mut self, request: PendingRequest) {
        let mut locked = self.pending.lock().expect("Lock is always successful except when poisoned. If poisened it will be poisened forever. We panic here because we can't recover from this.");
        let key = PendingRequestKey {
            forward_query_id: request.forward_query_id,
            to: request.to,
        };
        locked.insert(key, request);
    }

    /// Remove a pending request by forward query id and from address
    pub fn remove_by_forward_id(&mut self, forward_query_id: &u16, from: &SocketAddr) -> Option<PendingRequest> {
        let mut locked = self.pending.lock().expect("Lock is always successful except when poisoned. If poisened it will be poisened forever. We panic here because we can't recover from this.");
        let key = PendingRequestKey {
            forward_query_id: *forward_query_id,
            to: *from,
        };
        locked.remove(&key)
    }

    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
