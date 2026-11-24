mod mdns;
mod ssdp;
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
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    
    let (config, config_data) = AppConfig::load_from_file_with_data(&args.config)?;
    let config_arc = Arc::new(config);
    let (config_tx, config_rx) = tokio::sync::watch::channel(config_arc.clone());

    let mut mgr_inner = CommandServerManager::new(
        config_arc.web_server.clone(),
        config_arc.tracking.clone(),
        config_arc.interfaces.clone(),
    );
    mgr_inner.set_config_context(args.config.clone(), config_data, config_tx);
    let manager = Arc::new(Mutex::new(mgr_inner));

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

    let reflector = Reflector::new(config_rx.clone(), manager.clone());
    
    let _reflector_handle = tokio::spawn(async move {
        reflector.run().await;
    });

    let mut ssdp_reflector = crate::ssdp::SsdpReflector::new(config_rx, manager.clone(), args.verbose);
    let _ssdp_handle = tokio::spawn(async move {
        ssdp_reflector.run().await;
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
