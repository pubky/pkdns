use cli::run_cli;

mod cli;

mod commands;
mod external_ip;
mod helpers;
mod pkarr_packet;
mod simple_zone;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    run_cli().await;
    Ok(())
}
