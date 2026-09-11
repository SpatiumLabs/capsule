use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "capsule", about = "CLI for Capsule sandbox platform")]
pub(crate) struct Args {
    #[arg(long, global = true, help = "API base URL [env: CAPSULE_API_URL]")]
    pub api_url: Option<String>,

    #[arg(long, global = true, help = "API token [env: CAPSULE_API_TOKEN]")]
    pub token: Option<String>,

    #[arg(short, long, global = true, action = clap::ArgAction::Count, help = "Increase verbosity (-v, -vv, -vvv)")]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub(crate) enum Commands {
    /// Create a new sandbox
    Create(CreateArgs),
    /// List sandboxes
    List(ListArgs),
    /// Get sandbox details
    Get(GetArgs),
    /// SSH into a sandbox via WebSocket tunnel
    Ssh(SshArgs),
    /// Build reproducible rootfs images
    Image(ImageArgs),
}

#[derive(clap::Args)]
pub(crate) struct CreateArgs {
    #[arg(long, help = "Sandbox ID (auto-generated if omitted)")]
    pub id: Option<String>,

    #[arg(
        long,
        help = "Comma-separated ports to expose (e.g. 3000,8080)",
        value_delimiter = ','
    )]
    pub ports: Option<Vec<u16>>,

    #[arg(long, help = "Runtime backend (firecracker, qemu, remote-firecracker)")]
    pub runtime: Option<String>,

    #[arg(long, help = "Memory in MB")]
    pub memory_mb: Option<u64>,

    #[arg(long, help = "Number of vCPUs")]
    pub vcpus: Option<u32>,

    #[arg(long, help = "SSH public key content")]
    pub ssh_key: Option<String>,

    #[arg(long, default_value = "ed25519", help = "SSH key type (ed25519, rsa)")]
    pub ssh_key_type: String,

    #[arg(long, help = "Idle timeout in seconds")]
    pub idle_timeout_secs: Option<u64>,
}

#[derive(clap::Args)]
pub(crate) struct ListArgs {
    #[arg(long, default_value = "50", help = "Max results (1-250)")]
    pub limit: usize,
}

#[derive(clap::Args)]
pub(crate) struct GetArgs {
    pub id: String,
}

#[derive(clap::Args)]
pub(crate) struct SshArgs {
    pub id: String,
}

#[derive(clap::Args)]
pub(crate) struct ImageArgs {
    #[command(subcommand)]
    pub command: ImageCommands,
}

#[derive(Subcommand)]
pub(crate) enum ImageCommands {
    /// Build a rootfs image from a definition file
    Build {
        #[arg(short = 'c', long, value_name = "FILE")]
        config: camino::Utf8PathBuf,

        #[arg(short = 'l', long, value_name = "FILE")]
        lock_file: Option<camino::Utf8PathBuf>,

        #[arg(long, value_name = "FILE")]
        guest_agent: Option<camino::Utf8PathBuf>,

        #[arg(short = 'o', long, value_name = "DIR", default_value = "output")]
        output_dir: camino::Utf8PathBuf,

        #[arg(
            short = 'w',
            long,
            value_name = "DIR",
            default_value = "/var/tmp/capsule-build"
        )]
        work_dir: camino::Utf8PathBuf,

        #[arg(long)]
        locked: bool,
    },
    /// Generate a lock file from an image definition
    Lock {
        #[arg(short = 'c', long, value_name = "FILE")]
        config: camino::Utf8PathBuf,

        #[arg(short = 'o', long, value_name = "FILE")]
        output: camino::Utf8PathBuf,
    },
}
