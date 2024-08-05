use cli::run_cli;

mod cli;

mod simple_zone;
mod pkarr_packet;
mod pkarr_publisher;
mod commands;


#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    run_cli().await;
    Ok(())
}
