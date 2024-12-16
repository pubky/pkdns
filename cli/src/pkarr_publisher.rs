use std::{sync::mpsc::channel, io::{self, Write}};
use chrono;
use pkarr::{PkarrClient, Settings, SignedPacket};

use crate::helpers::construct_pkarr_client;

pub struct PkarrPublisher {
    pub packet: SignedPacket
}

/**
 * Continuously publishes dns records to pkarr
 */
impl PkarrPublisher {
    pub fn new(packet: SignedPacket) -> Self {
        PkarrPublisher {
            packet
        }
    }
    
    pub fn run_once(&self) -> () {
        let client = construct_pkarr_client();
        print!("Hang on...");
        io::stdout().flush().unwrap();
        let result = client.publish(&self.packet);
        print!("\r");
        // std::io::stdout().flush();
        if result.is_ok() {
            println!("{} Successfully announced.", chrono::offset::Local::now());
        } else {
            println!("{} Error {}", chrono::offset::Local::now(), result.unwrap_err().to_string());
        };

    }

    pub fn run(&self, interval: chrono::Duration){
        let (tx, rx) = channel();
    
        ctrlc::set_handler(move || tx.send(()).expect("Could not send signal on channel."))
            .expect("Error setting Ctrl-C handler");
        loop {
            self.run_once();

            let wait_result = rx.recv_timeout(interval.to_std().expect("Valid duration expected"));
            if wait_result.is_ok() {
                break;
            }
        }
        println!();
        println!("Got it! Exiting...");
    }
}
