#![allow(unused)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Instant,
};

use tokio::sync::oneshot;

#[derive(Debug)]
pub struct PendingRequest {
    pub to: SocketAddr,
    pub sent_at: Instant,
    pub original_query_id: u16,
    pub forward_query_id: u16,
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
    pub fn insert(&mut self, request: PendingRequest) {
        let mut locked = self.pending.lock().expect("Lock success");
        let key = PendingRequestKey {
            forward_query_id: request.forward_query_id.clone(),
            to: request.to.clone(),
        };
        locked.insert(key, request);
    }

    pub fn remove_by_forward_id(&mut self, forward_query_id: &u16, from: &SocketAddr) -> Option<PendingRequest> {
        let mut locked = self.pending.lock().expect("Lock success");
        let key = PendingRequestKey {
            forward_query_id: forward_query_id.clone(),
            to: from.clone(),
        };
        locked.remove(&key)
    }

    pub fn new() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
