mod cli;
mod client;
mod config;
mod ssh;

use capsule_core::{RuntimeType, SandboxSpec};
use clap::Parser;
use cli::{Args, Commands, ImageCommands};
use client::ApiClient;
use config::Config;

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let log_filter = match args.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    let telemetry_config = capsule_telemetry::TelemetryConfig {
        settings: &capsule_telemetry::TelemetrySettings {
            log: capsule_telemetry::LogSettings {
                format: capsule_telemetry::LogFormat::Pretty,
                filter: log_filter.to_string(),
                ..Default::default()
            },
            metrics: capsule_telemetry::MetricsSettings {
                service_name: "capsule-cli".to_string(),
                ..Default::default()
            },
            ..Default::default()
        },
    };

    let _driver =
        capsule_telemetry::init(telemetry_config).expect("failed to initialize telemetry");

    let mut config = Config::from_env();
    config.apply_overrides(args.api_url, args.token);
    if let Err(msg) = config.validate() {
        eprintln!("error: {msg}");
        std::process::exit(1);
    }

    let client = ApiClient::new(config.api_url, config.token);

    let result = match args.command {
        Commands::Image(ia) => match ia.command {
            ImageCommands::Build {
                config,
                lock_file,
                guest_agent,
                output_dir,
                work_dir,
                locked,
            } => {
                let builder = capsule_image::RootfsBuilder {
                    definition_path: config,
                    lock_path: lock_file,
                    work_dir,
                    output_dir,
                    guest_agent_path: guest_agent,
                    locked,
                    signing_key_path: None,
                    signer_identity: None,
                };

                builder
                    .build()
                    .map(|output| {
                        println!("rootfs: {} ({})", output.rootfs.path, output.rootfs.digest);
                        println!("manifest: {}", output.manifest_path);
                    })
                    .map_err(|e| e.to_string())
            }

            ImageCommands::Lock { config, output } => {
                capsule_image::definition::ImageDefinition::load(&config)
                    .and_then(|definition| {
                        capsule_image::resolve::create_lock(&definition, &output)
                    })
                    .map(|lock| {
                        println!("lock: {} ({})", output, lock.metadata.version);
                    })
                    .map_err(|e| e.to_string())
            }
        },
        Commands::Create(ca) => {
            let spec = SandboxSpec {
                id: ca.id,
                ports: ca.ports,
                runtime: ca.runtime.map(|r| parse_runtime(&r)),
                memory_mb: ca.memory_mb,
                vcpus: ca.vcpus,
                idle_timeout_secs: ca.idle_timeout_secs,
                ssh_public_key: ca.ssh_key,
                ssh_key_type: Some(ca.ssh_key_type),
                env: None,
                image_id: None,
                image_digest: None,
                credential_request: None,
            };
            client.create_sandbox(&spec).await.map(|info| {
                println!("{}", serde_json::to_string_pretty(&info).unwrap());
            })
        }
        Commands::List(la) => client.list_sandboxes(la.limit).await.map(|page| {
            println!("{}", serde_json::to_string_pretty(&page).unwrap());
        }),
        Commands::Get(ga) => client.get_sandbox(&ga.id).await.map(|info| {
            println!("{}", serde_json::to_string_pretty(&info).unwrap());
        }),
        Commands::Ssh(sa) => ssh::ssh_into_sandbox(&client, &sa.id).await,
    };

    if let Err(msg) = result {
        eprintln!("error: {msg}");
        std::process::exit(1);
    }
}

fn parse_runtime(name: &str) -> RuntimeType {
    match name.to_lowercase().as_str() {
        "firecracker" => RuntimeType::Firecracker,
        "qemu" => RuntimeType::Qemu,
        "remote-firecracker" => RuntimeType::RemoteFirecracker,
        other => {
            eprintln!("warning: unknown runtime '{other}', defaulting to firecracker");
            RuntimeType::Firecracker
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_runtime_known_names() {
        assert_eq!(parse_runtime("firecracker"), RuntimeType::Firecracker);
        assert_eq!(parse_runtime("qemu"), RuntimeType::Qemu);
        assert_eq!(
            parse_runtime("remote-firecracker"),
            RuntimeType::RemoteFirecracker
        );
    }

    #[test]
    fn parse_runtime_case_insensitive() {
        assert_eq!(parse_runtime("QEMU"), RuntimeType::Qemu);
        assert_eq!(parse_runtime("Firecracker"), RuntimeType::Firecracker);
    }

    #[test]
    fn parse_runtime_unknown_defaults_to_firecracker() {
        assert_eq!(parse_runtime("docker"), RuntimeType::Firecracker);
    }
}
