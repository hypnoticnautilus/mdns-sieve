mod mdns;
mod config;
mod database;
mod server;
mod reflector;

use std::sync::Arc;
use tokio::sync::Mutex;
use clap::Parser;
use crate::config::AppConfig;
use crate::server::{CommandServerManager, run_command_server};
use crate::reflector::Reflector;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "/etc/mdns-sieve.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    let config = AppConfig::load_from_file(&args.config)?;
    let config_arc = Arc::new(config);

    let manager = Arc::new(Mutex::new(CommandServerManager::new(
        config_arc.web_server.clone(),
        config_arc.tracking.clone(),
    )));

    if let Some(ws_cfg) = &config_arc.web_server {
        if ws_cfg.enabled {
            let mgr_clone = manager.clone();
            let host = ws_cfg.host.clone();
            let port = ws_cfg.port;
            tokio::spawn(async move {
                run_command_server(mgr_clone, host, port).await;
            });
        }
    }

    let reflector = Reflector::new(config_arc.clone(), manager.clone());
    
    let reflector_handle = tokio::spawn(async move {
        reflector.run().await;
    });

    // Handle signals for graceful shutdown
    match signal::ctrl_c().await {
        Ok(()) => {
            println!("Received Ctrl-C, shutting down gracefully...");
        },
        Err(err) => {
            eprintln!("Unable to listen for shutdown signal: {}", err);
        },
    }

    let mut mgr = manager.lock().await;
    mgr.flush_stats(true);
    
    Ok(())
}
