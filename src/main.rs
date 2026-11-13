//! Notary: RPKI Route Origin Validation checker.

mod api;
mod aspa;
mod audit;
mod bench;
mod commands;
mod config;
mod daemon;
mod history;
mod http;
mod irr;
mod prefix;
mod rtr;
mod slurm;
mod sources;
mod state;
mod validator;
mod vrp;
mod watch;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Parser, Subcommand};
use llcforge_alert::cli::{run_silence_command, ServiceCommand, SilenceCommand};
use llcforge_alert::{init_logging, run_service_command, LogFormat};

use crate::aspa::Direction;
use crate::rtr::transport::TransportConfig;

#[derive(Parser)]
#[command(
    name = "notary",
    version,
    about = "RPKI Route Origin Validation checker"
)]
struct Cli {
    /// Configuration file (used by run, service, silence and history).
    #[arg(long, short, global = true, default_value = "notary.toml")]
    config: PathBuf,
    /// Log format: text or json.
    #[arg(long, global = true, default_value = "text", value_parser = parse_log_format)]
    log_format: LogFormat,
    #[command(subcommand)]
    command: Command,
}

fn parse_log_format(s: &str) -> Result<LogFormat, String> {
    s.parse()
}

/// Where VRPs come from for one-shot commands.
#[derive(Args, Clone, Default)]
pub struct SourceArgs {
    /// JSON VRP export ({"roas":[...]}) as a path or http(s):// URL.
    #[arg(long, conflicts_with = "rtr")]
    pub vrps: Option<String>,
    /// RTR cache: host:port, tls://host[:port] or ssh://user@host[:port].
    #[arg(long)]
    pub rtr: Option<String>,
    /// Highest RTR version to offer (2 = ASPA); falls back automatically.
    #[arg(long, value_parser = clap::value_parser!(u8).range(0..=2))]
    pub rtr_version: Option<u8>,
    /// RFC 8416 SLURM file to apply (repeatable).
    #[arg(long)]
    pub slurm: Vec<PathBuf>,
    #[command(flatten)]
    pub transport: TransportConfig,
}

/// Prefix announcement source for suggest / audit.
#[derive(Args, Clone)]
pub struct PrefixArgs {
    /// ripestat, bgptools, or a Pathology API URL (token: PATHOLOGY_API_TOKEN).
    #[arg(long, default_value = "ripestat")]
    pub prefixes_from: String,
    /// bgp.tools User-Agent naming you and a contact (required for bgptools).
    #[arg(long)]
    pub user_agent: Option<String>,
    /// Upper bound for prefixes fetched for the AS.
    #[arg(long, default_value_t = 10_000)]
    pub max_prefixes: usize,
}

#[derive(Subcommand)]
enum Command {
    /// Validate one route, or many from a file / stdin, and explain the result.
    ///
    /// Exit status: 0 Valid, 2 Invalid, 3 NotFound, 1 error. With --file:
    /// 2 if any route is Invalid, else 3 if any is NotFound, 1 on bad lines.
    Check {
        /// Route prefix, e.g. 198.51.100.0/24.
        #[arg(required_unless_present = "file")]
        prefix: Option<String>,
        /// Origin AS, e.g. AS64500 or 64500.
        #[arg(required_unless_present = "file")]
        asn: Option<String>,
        /// Bulk mode: one "prefix asn" per line ("-" = stdin; '#' comments).
        #[arg(long, conflicts_with_all = ["prefix", "asn"])]
        file: Option<String>,
        #[command(flatten)]
        source: SourceArgs,
        /// Print JSON (bulk mode: one JSON object per line).
        #[arg(long)]
        json: bool,
    },
    /// Run the daemon: keep VRPs fresh, watch routes, alert, serve the API.
    Run,
    /// Suggest minimal ROAs (maxLength = prefix length) for an AS's announcements.
    Suggest {
        /// AS number, e.g. AS64500.
        asn: String,
        #[command(flatten)]
        prefixes: PrefixArgs,
        /// Compare with current VRPs (optional).
        #[command(flatten)]
        source: SourceArgs,
        #[arg(long)]
        json: bool,
    },
    /// RFC 9319 audit: VRPs of an AS whose maxLength authorises unannounced prefixes.
    Audit {
        asn: String,
        #[command(flatten)]
        prefixes: PrefixArgs,
        #[command(flatten)]
        source: SourceArgs,
        #[arg(long)]
        json: bool,
    },
    /// Compare an AS's IRR route/route6 objects with its ROAs.
    Irr {
        asn: String,
        /// "ripe" (RIPE DB REST) or whois://host[:port] (e.g. whois://whois.radb.net).
        #[arg(long, default_value = "ripe")]
        irr: String,
        #[command(flatten)]
        source: SourceArgs,
        #[arg(long)]
        json: bool,
    },
    /// Verify an AS_PATH with ASPA (neighbor first, origin last).
    ///
    /// Exit status: 0 Valid, 2 Invalid, 3 Unknown, 1 error.
    Aspa {
        /// AS path, e.g. "64502 64501 64500".
        path: String,
        #[arg(long, value_enum, default_value_t = Direction::Upstream)]
        direction: Direction,
        #[command(flatten)]
        source: SourceArgs,
        #[arg(long)]
        json: bool,
    },
    /// Diff two VRP sources (JSON path/URL or rtr:// tls:// ssh:// cache).
    ///
    /// Exit status: 0 identical, 2 different, 1 error.
    Diff {
        a: String,
        b: String,
        #[arg(long, value_parser = clap::value_parser!(u8).range(0..=2), default_value_t = 1)]
        rtr_version: u8,
        #[command(flatten)]
        transport: TransportConfig,
        /// Print at most this many differing VRPs per side.
        #[arg(long, default_value_t = 50)]
        show: usize,
        #[arg(long)]
        json: bool,
    },
    /// Query the VRP change history recorded by the daemon.
    History {
        #[arg(long)]
        prefix: Option<String>,
        #[arg(long)]
        asn: Option<String>,
        /// RFC 3339 lower bound, e.g. 2026-01-31T00:00:00Z.
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Data directory (default: from --config, else the platform default).
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Measure validation, parsing and decoding speed on this machine.
    Bench {
        /// Benchmark against a real JSON export instead of synthetic data.
        #[arg(long)]
        vrps: Option<String>,
        #[arg(long, default_value_t = 600_000)]
        v4: usize,
        #[arg(long, default_value_t = 200_000)]
        v6: usize,
        #[arg(long, default_value_t = 2_000_000)]
        lookups: usize,
        #[arg(long)]
        json: bool,
    },
    /// Manage silences / maintenance windows.
    Silence {
        #[command(subcommand)]
        cmd: SilenceCommand,
    },
    /// Install, remove or run as a system service.
    Service {
        #[command(subcommand)]
        cmd: ServiceCommand,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let level = match cli.command {
        Command::Run | Command::Service { .. } => "info",
        _ => "warn",
    };
    if let Err(e) = init_logging(cli.log_format, level, None) {
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }
    let config = cli.config;
    let result = match cli.command {
        Command::Run => llcforge_alert::service::run_foreground(config, daemon::daemon)
            .map(|()| ExitCode::SUCCESS),
        Command::Service { cmd } => {
            run_service_command(&daemon::SPEC, cmd.into_action(config), daemon::daemon)
                .map(|()| ExitCode::SUCCESS)
        }
        Command::Silence { cmd } => commands::silence_path(&config)
            .and_then(|p| run_silence_command(cmd, &p))
            .map(|()| ExitCode::SUCCESS),
        Command::Bench {
            vrps,
            v4,
            v6,
            lookups,
            json,
        } => commands::block_on(commands::bench(vrps, v4, v6, lookups, json)),
        Command::History {
            prefix,
            asn,
            since,
            limit,
            data_dir,
            json,
        } => commands::history(&config, prefix, asn, since, limit, data_dir, json),
        Command::Check {
            prefix,
            asn,
            file,
            source,
            json,
        } => commands::block_on(async move {
            match file {
                Some(f) => commands::check_bulk(&f, &source, json).await,
                None => {
                    commands::check(
                        prefix.as_deref().unwrap_or_default(),
                        asn.as_deref().unwrap_or_default(),
                        &source,
                        json,
                    )
                    .await
                }
            }
        }),
        Command::Suggest {
            asn,
            prefixes,
            source,
            json,
        } => commands::block_on(commands::suggest(&asn, &prefixes, &source, json)),
        Command::Audit {
            asn,
            prefixes,
            source,
            json,
        } => commands::block_on(commands::audit(&asn, &prefixes, &source, json)),
        Command::Irr {
            asn,
            irr,
            source,
            json,
        } => commands::block_on(commands::irr(&asn, &irr, &source, json)),
        Command::Aspa {
            path,
            direction,
            source,
            json,
        } => commands::block_on(commands::aspa(&path, direction, &source, json)),
        Command::Diff {
            a,
            b,
            rtr_version,
            transport,
            show,
            json,
        } => commands::block_on(commands::diff(&a, &b, rtr_version, &transport, show, json)),
    };
    match result {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn config_flag_works_before_and_after_subcommand() {
        for args in [
            &["notary", "run", "--config", "x.toml"][..],
            &["notary", "--config", "x.toml", "run"],
            &["notary", "service", "run", "--config", "x.toml"],
        ] {
            let c = Cli::try_parse_from(args).unwrap();
            assert_eq!(c.config, PathBuf::from("x.toml"));
        }
        assert!(Cli::try_parse_from(["notary", "check", "192.0.2.0/24"]).is_err());
        assert!(Cli::try_parse_from(["notary", "check", "--file", "-", "--vrps", "x"]).is_ok());
        assert!(Cli::try_parse_from(["notary", "--log-format", "yaml", "run"]).is_err());
    }
}
