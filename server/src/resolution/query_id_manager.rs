#![allow(unused)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
};

/**
 * Thread-safe QueryIdManager.
 * Use `.clone()` to give each thread one store struct.
 * The data will stay shared.
 */
#[derive(Debug, Clone)]
pub struct QueryIdManager {
    ids: Arc<Mutex<HashMap<SocketAddr, u16>>>,
}

impl QueryIdManager {
    /**
     * Gets the next available query id
     */
    pub fn get_next(&mut self, server: &SocketAddr) -> u16 {
        let mut locked = self.ids.lock().expect("Lock success");
        let current = match locked.get(server) {
            Some(val) => *val,
            None => 0,
        };
        let next = if current == u16::MAX { 0 } else { current + 1 };
        locked.insert(*server, next);
        next
    }

    pub fn new() -> Self {
        Self {
            ids: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
