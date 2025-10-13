// tests/relay_reachability_test.rs

use tor_client::{TorClient, TorConfig, DirectoryClient};
use std::time::Duration;

#[tokio::test]
async fn test_relay_reachability() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== Testing Relay Reachability ===\n");

    // Create directory client
    let directory = DirectoryClient::new(vec!["tor-collector".to_string()]);
    
    // Fetch consensus
    println!("Fetching consensus...");
    let consensus = directory.fetch_consensus().await
        .expect("Failed to fetch consensus");
    
    println!("✓ Fetched {} relays from consensus\n", consensus.relays.len());

    // Test each hop type
    for hop in 0..3 {
        let hop_name = match hop {
            0 => "Guard",
            1 => "Middle",
            2 => "Exit",
            _ => "Unknown",
        };
        
        println!("--- Testing {} Relay (hop {}) ---", hop_name, hop);
        
        // Try up to 3 relays for this hop (in case some are temporarily down)
        let mut success = false;
        for attempt in 1..=3 {
            // Select relay for this hop
            let relay = directory.select_relay(hop).await
                .expect(&format!("Failed to select {} relay", hop_name));
            
            println!("Attempt {}: {} ({})", attempt, relay.nickname, relay.address);
            println!("  Flags: {:?}", relay.flags);
            println!("  Bandwidth: {} KB/s", relay.bandwidth);
            
            // Test TCP reachability
            print!("  Testing TCP connection... ");
            match tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::TcpStream::connect(relay.address)
            ).await {
                Ok(Ok(stream)) => {
                    drop(stream);
                    println!("✓ REACHABLE");
                    success = true;
                    break;
                }
                Ok(Err(e)) => {
                    println!("✗ UNREACHABLE: {}", e);
                    if attempt == 3 {
                        panic!("{} relay selection failed after 3 attempts", hop_name);
                    }
                }
                Err(_) => {
                    println!("✗ TIMEOUT");
                    if attempt == 3 {
                        panic!("{} relay selection failed after 3 attempts (all timed out)", hop_name);
                    }
                }
            }
        }
        
        if success {
            println!("✓ Found reachable {} relay\n", hop_name);
        }
    }

    println!("=== All Relays Reachable ===\n");
}

#[tokio::test]
async fn test_circuit_with_reachability() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== Testing Full Circuit Creation with Reachability ===\n");

    let config = TorConfig {
        directory_authorities: vec!["tor-collector".to_string()],
        socks_port: 9051, // Different port to avoid conflicts
        ..Default::default()
    };

    let client = TorClient::start(config).await
        .expect("Failed to start Tor client");

    // Create a circuit
    println!("Creating circuit...");
    let circuit_id = client.create_circuit(3).await
        .expect("Failed to create circuit");

    println!("✓ Circuit {} created and all relays are reachable!\n", circuit_id);
}

#[tokio::test]
async fn test_multiple_circuits_reachability() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== Testing Multiple Circuits for Reachability ===\n");

    let config = TorConfig {
        directory_authorities: vec!["tor-collector".to_string()],
        socks_port: 9052, // Different port
        ..Default::default()
    };

    let client = TorClient::start(config).await
        .expect("Failed to start Tor client");

    let num_circuits = 3;
    
    for i in 0..num_circuits {
        println!("--- Creating Circuit {} ---", i + 1);
        
        match client.create_circuit(3).await {
            Ok(circuit_id) => {
                println!("✓ Circuit {} created successfully\n", circuit_id);
            }
            Err(e) => {
                println!("✗ Circuit {} failed: {:?}\n", i + 1, e);
                panic!("Circuit creation failed");
            }
        }
    }

    println!("=== All {} Circuits Created Successfully ===\n", num_circuits);
}

#[tokio::test]
async fn test_relay_flags_validation() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init()
        .ok();

    println!("\n=== Testing Relay Flag Validation ===\n");

    let directory = DirectoryClient::new(vec!["tor-collector".to_string()]);
    let consensus = directory.fetch_consensus().await.unwrap();

    // Test Guard relay
    println!("--- Testing Guard Relay ---");
    let guard = directory.select_relay(0).await.unwrap();
    println!("Guard: {} - Flags: {:?}", guard.nickname, guard.flags);
    
    assert!(guard.flags.iter().any(|f| matches!(f, tor_client::directory::RelayFlag::Guard)), 
        "Guard relay must have Guard flag");
    assert!(guard.flags.iter().any(|f| matches!(f, tor_client::directory::RelayFlag::Fast)), 
        "Guard relay must have Fast flag");
    println!("✓ Guard has correct flags\n");

    // Test Middle relay
    println!("--- Testing Middle Relay ---");
    let middle = directory.select_relay(1).await.unwrap();
    println!("Middle: {} - Flags: {:?}", middle.nickname, middle.flags);
    
    assert!(!middle.flags.iter().any(|f| matches!(f, tor_client::directory::RelayFlag::Guard)), 
        "Middle relay must NOT have Guard flag");
    assert!(!middle.flags.iter().any(|f| matches!(f, tor_client::directory::RelayFlag::Exit)), 
        "Middle relay must NOT have Exit flag");
    assert!(middle.flags.iter().any(|f| matches!(f, tor_client::directory::RelayFlag::Fast)), 
        "Middle relay must have Fast flag");
    println!("✓ Middle has correct flags (no Guard/Exit)\n");

    // Test Exit relay
    println!("--- Testing Exit Relay ---");
    let exit = directory.select_relay(2).await.unwrap();
    println!("Exit: {} - Flags: {:?}", exit.nickname, exit.flags);
    
    assert!(exit.flags.iter().any(|f| matches!(f, tor_client::directory::RelayFlag::Exit)), 
        "Exit relay must have Exit flag");
    assert!(exit.flags.iter().any(|f| matches!(f, tor_client::directory::RelayFlag::Fast)), 
        "Exit relay must have Fast flag");
    println!("✓ Exit has correct flags\n");

    println!("=== All Flag Validations Passed ===\n");
}