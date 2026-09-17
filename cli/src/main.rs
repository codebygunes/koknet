use clap::{Parser, Subcommand};
use futures::StreamExt;
use libp2p::identity;
use koknet_core::identity::NodeIdentity;
use storage::db::KoknetDb;
use transport::p2p::build_swarm;

#[derive(Parser)]
#[command(name = "koknet")]
#[command(about = "Zero-Metadata, Local-First, and DPI-Evading P2P Core", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Starts a new Koknet peer node
    Start {
        #[arg(short, long, default_value = "koknet_node.sqlite")]
        db: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Start { db } => {
            println!("[*] Initializing Koknet Node...");

            // 1. Generate cryptographic identity
            let _identity = NodeIdentity::generate();
            println!("[+] Node Identity (Public Key) generated successfully.");

            // 2. Initialize local-first SQLite database
            let _db_engine = KoknetDb::new(&db)?;
            println!("[+] Local-First SQLite Database initialized at: {}", db);

            // 3. Build libp2p Swarm
            let local_key = identity::Keypair::generate_ed25519();
            let mut swarm = build_swarm(local_key).await?;
            println!("[+] P2P Network Swarm built successfully.");

            // Listen on TCP/IP interface
            swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;
            println!("[*] Koknet node is active and listening for peers...");

            // Event loop using futures StreamExt `.next()` trait
            loop {
                if let Some(event) = swarm.next().await {
                    println!("[P2P Event]: {:?}", event);
                }
            }
        }
    }
}