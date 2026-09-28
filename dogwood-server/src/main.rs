//! `dogwood-server` — the Dogwood policy server and its control-plane CLI.
//!
//! One binary, two tiers of subcommand, split exactly as `DESIGN.md` §8
//! specifies:
//!
//! - `dogwood-server run` — the server itself. Owns the policy set, the compiled
//!   temporal monitor, and the durable event log as its own OS principal, and
//!   serves the schema-driven `submit` wire API (§10) over a Unix socket.
//! - `dogwood-server policy install|show`, `status`, `checkpoint` — the
//!   **control plane**: a client over the privileged socket. Authorized by
//!   kernel peer-credential against a uid allowlist (§8.1), and never reachable
//!   over the agent's data path.
//! - `dogwood-server submit` / `ping` — data-path clients, for driving a running
//!   server by hand.
//!
//! The file-only commands (`dogwood validate`, `lower`, `replay`) stay in
//! `dogwood-cli`: those operate on files, not on a live server.
//!
//! # What this adds over embedding the library
//!
//! `dogwood-local-engine` is embeddable and gives correctness and durability. It
//! does **not** give tamper-resistance: a process that links it can rewrite the
//! policy set it is being judged by. This binary is where that changes, by moving
//! the policy set behind a process boundary the monitored agent is not on the
//! inside of (§7). The prerequisite §7.1 states plainly: **run the server as one
//! uid and the monitored agent as a different, lower-privileged uid.** Same uid,
//! no boundary.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use dogwood_server::client::{ControlClient, DataClient};
use dogwood_server::peer::ControlAllowlist;
use dogwood_server::protocol::{
    ControlRequest, ControlResponse, DataRequest, DataResponse, WireEvent, WireVerb,
};
use dogwood_server::server::{self, Paths, Server};

/// The default state directory, under the user's home.
fn default_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".dogwood")
}

#[derive(Parser)]
#[command(
    name = "dogwood-server",
    about = "The Dogwood policy server and its control plane",
    version
)]
struct Cli {
    /// The server's state directory (durable store + sockets).
    #[arg(long, global = true)]
    dir: Option<PathBuf>,

    /// Emit machine-readable JSON instead of human-readable text.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server.
    Run {
        /// Snapshot the monitor state every N events (`DESIGN.md` §6.3). `0`
        /// disables periodic snapshots; a clean shutdown still snapshots.
        #[arg(long, default_value_t = 10_000)]
        snapshot_interval: u64,
        /// Additional uids permitted on the control plane, beyond the server's
        /// own uid (§8.1). Widening this widens who may author policy.
        #[arg(long, value_delimiter = ',')]
        control_uid: Vec<u32>,
    },

    /// Control plane: manage the installed policy set.
    #[command(subcommand)]
    Policy(PolicyCommand),

    /// Control plane: report what is installed and running.
    Status,

    /// Control plane: force a state snapshot now.
    Checkpoint,

    /// Data plane: submit one event and print the outcome.
    Submit {
        /// The qualified action, for example, `Drupe::Action::Login`.
        action: String,
        /// The event kind, e.g. `request`.
        kind: String,
        /// The request principal's entity uid, e.g. `User::"alice"`.
        #[arg(long)]
        principal: Option<String>,
        /// The request resource's entity uid.
        #[arg(long)]
        resource: Option<String>,
        /// The logged temporal record, as a JSON object of groups:
        /// `'{"input": {"user": "alice"}}'`.
        #[arg(long)]
        logged: Option<String>,
        /// The request-only context a policy reads as `context.<group>.<name>`.
        #[arg(long)]
        context: Option<String>,
    },

    /// Data plane: check that the server is alive.
    Ping,
}

#[derive(Subcommand)]
enum PolicyCommand {
    /// Install a policy set, replacing what is running — the declarative path.
    ///
    /// The server validates the bundle against the schema before accepting it and
    /// swaps atomically; a rejected install leaves the running set serving (§8).
    /// This is also where the event schema is configured, once: it is fixed
    /// thereafter, and a later install that changes it is rejected.
    /// Every policy is reborn
    /// (`[DeleteAll; Add …]`, §2.8); use the incremental verbs below to keep
    /// existing history.
    Install {
        /// The `.dw` policy file.
        policy: PathBuf,
        /// The Cedar action schema (`.cedarschema`).
        #[arg(long)]
        action_schema: PathBuf,
        /// The event-schema DSL (`.dwschema`). Omit to use the default schema.
        #[arg(long)]
        event_schema: Option<PathBuf>,
    },
    /// Add one policy, born fresh; prints the id the engine mints for it (§2.5).
    Add {
        /// The `.dw` file — a single policy.
        policy: PathBuf,
    },
    /// Replace one policy's content by id. Same id, but its history resets
    /// ("update means reset", §2.2).
    Update {
        /// The policy handle (from `policy list`).
        id: String,
        /// The `.dw` file — a single policy.
        policy: PathBuf,
    },
    /// Remove one policy by id.
    Delete {
        /// The policy handle (from `policy list`).
        id: String,
    },
    /// Clear one policy's accumulated history; its content is unchanged (§2.2).
    Reset {
        /// The policy handle (from `policy list`).
        id: String,
    },
    /// Remove every policy. The schema is kept and the empty set stays installed,
    /// so decisions fail closed (§2.1).
    DeleteAll,
    /// Clear every policy's history; all policies are kept (§2.1).
    ResetAll,
    /// Revalidate + re-lower the whole set under a new action schema (§2.7). All
    /// history carries if it validates; the batch is rejected if it does not.
    SetActionSchema {
        /// The Cedar action schema (`.cedarschema`).
        action_schema: PathBuf,
    },
    /// Append a fragment onto the current action schema, atomically (§2.7) — add a
    /// new entity/action without a fetch-then-set round trip a concurrent change
    /// could invalidate. All history carries if the merged schema validates; the
    /// batch is rejected (nothing changes) if it does not.
    AppendActionSchema {
        /// A Cedar schema fragment (`.cedarschema`) with the new declarations.
        fragment: PathBuf,
    },
    /// List the installed policies (id + created/updated), paginated (§2.7).
    List {
        /// Cap the page size; omit to return all.
        #[arg(long)]
        max_results: Option<usize>,
        /// Resume after this handle (the hint a previous page prints).
        #[arg(long)]
        after: Option<String>,
    },
    /// Print one policy's source by id.
    Get {
        /// The policy handle (from `policy list`).
        id: String,
    },
    /// Print the store's schemas: the original action schema and the configured
    /// event schema (§2.7).
    Schema,
    /// Print the whole installed policy source (every policy, concatenated).
    Show,
}

fn main() -> std::process::ExitCode {
    let cli = Cli::parse();
    let paths = Paths::new(cli.dir.clone().unwrap_or_else(default_dir));

    match run(&cli, &paths) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            if cli.json {
                println!("{}", serde_json::json!({ "error": message }));
            } else {
                eprintln!("dogwood-server: {message}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli, paths: &Paths) -> Result<(), String> {
    match &cli.command {
        Command::Run {
            snapshot_interval,
            control_uid,
        } => {
            let allowlist = ControlAllowlist::with_extra(control_uid.iter().copied());
            let server = Server::open(paths.clone(), allowlist.clone(), *snapshot_interval)?;

            if !cli.json {
                eprintln!("dogwood-server {}", server::VERSION);
                eprintln!("  store:   {}", paths.store().display());
                // Both modes are printed because the asymmetry is the boundary,
                // and an operator debugging "the agent can't connect" needs to see
                // that the data socket is deliberately reachable while everything
                // else is not.
                eprintln!(
                    "  data:    {} (0666 in a 0711 dir — reachable by the agent's uid)",
                    paths.data_socket().display()
                );
                eprintln!(
                    "  control: {} (0700 in a 0700 dir — owner only)",
                    paths.control_socket().display()
                );
                eprintln!("  control uids: {:?}", allowlist.uids());
                // §7.1's prerequisite is the one deployment fact that determines
                // whether the boundary is real, so it is stated at every start
                // rather than left in the design doc.
                eprintln!(
                    "\nnote: tamper-resistance requires the monitored agent to run as a \
                     DIFFERENT,\n      lower-privileged uid than this server. Same uid, no \
                     boundary."
                );
            }
            server.serve()
        }

        Command::Policy(PolicyCommand::Install {
            policy,
            action_schema,
            event_schema,
        }) => {
            let policy_src = read(policy)?;
            let action_src = read(action_schema)?;
            let event_src = event_schema.as_ref().map(read).transpose()?;
            let response = control(
                paths,
                ControlRequest::Install {
                    policy: policy_src,
                    action_schema: action_src,
                    event_schema: event_src,
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::Add { policy }) => {
            let policy_src = read(policy)?;
            let response = control(
                paths,
                ControlRequest::Batch {
                    verbs: vec![WireVerb::Add { policy: policy_src }],
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::Update { id, policy }) => {
            let policy_src = read(policy)?;
            let response = control(
                paths,
                ControlRequest::Batch {
                    verbs: vec![WireVerb::Update {
                        id: id.clone(),
                        policy: policy_src,
                    }],
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::Delete { id }) => {
            let response = control(
                paths,
                ControlRequest::Batch {
                    verbs: vec![WireVerb::Delete { id: id.clone() }],
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::Reset { id }) => {
            let response = control(
                paths,
                ControlRequest::Batch {
                    verbs: vec![WireVerb::Reset { id: id.clone() }],
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::DeleteAll) => {
            let response = control(
                paths,
                ControlRequest::Batch {
                    verbs: vec![WireVerb::DeleteAll],
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::ResetAll) => {
            let response = control(
                paths,
                ControlRequest::Batch {
                    verbs: vec![WireVerb::ResetAll],
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::SetActionSchema { action_schema }) => {
            let action_src = read(action_schema)?;
            let response = control(
                paths,
                ControlRequest::Batch {
                    verbs: vec![WireVerb::SetActionSchema {
                        action_schema: action_src,
                    }],
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::AppendActionSchema { fragment }) => {
            let fragment_src = read(fragment)?;
            let response = control(
                paths,
                ControlRequest::Batch {
                    verbs: vec![WireVerb::AppendActionSchema {
                        fragment: fragment_src,
                    }],
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::List { max_results, after }) => {
            let response = control(
                paths,
                ControlRequest::List {
                    max_results: *max_results,
                    next_token: after.clone(),
                },
            )?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::Get { id }) => {
            let response = control(paths, ControlRequest::GetPolicyById { id: id.clone() })?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::Schema) => {
            let response = control(paths, ControlRequest::GetSchema)?;
            report_control(cli, &response)
        }

        Command::Policy(PolicyCommand::Show) => {
            let response = control(paths, ControlRequest::GetPolicy)?;
            report_control(cli, &response)
        }

        Command::Status => {
            let response = control(paths, ControlRequest::Status)?;
            report_control(cli, &response)
        }

        Command::Checkpoint => {
            let response = control(paths, ControlRequest::Checkpoint)?;
            report_control(cli, &response)
        }

        Command::Submit {
            action,
            kind,
            principal,
            resource,
            logged,
            context,
        } => {
            let mut event = WireEvent::new(action, kind);
            event.principal = principal.clone();
            event.resource = resource.clone();
            if let Some(src) = logged {
                event.logged = parse_bag(src, "--logged")?;
            }
            if let Some(src) = context {
                event.context = parse_bag(src, "--context")?;
            }
            let mut client = DataClient::connect(paths.data_socket())?;
            let response = client.call(&DataRequest::Submit { event })?;
            report_data(cli, &response)
        }

        Command::Ping => {
            let mut client = DataClient::connect(paths.data_socket())?;
            let response = client.call(&DataRequest::Ping)?;
            report_data(cli, &response)
        }
    }
}

/// Send one control request over the privileged socket.
fn control(paths: &Paths, request: ControlRequest) -> Result<ControlResponse, String> {
    ControlClient::connect(paths.control_socket())?.call(&request)
}

fn read(path: &PathBuf) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))
}

/// Parse a `--logged` / `--context` argument: a JSON object of groups.
fn parse_bag(src: &str, flag: &str) -> Result<serde_json::Map<String, serde_json::Value>, String> {
    match serde_json::from_str(src) {
        Ok(serde_json::Value::Object(map)) => Ok(map),
        Ok(_) => Err(format!("{flag} must be a JSON object of groups")),
        Err(e) => Err(format!("{flag}: {e}")),
    }
}

/// Print a control response.
///
/// An `Error` response is returned as `Err` so the process exit code reflects it
/// — a rejected `apply` must fail a script, not print a message and succeed.
fn report_control(cli: &Cli, response: &ControlResponse) -> Result<(), String> {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(response).map_err(|e| e.to_string())?
        );
        return match response {
            ControlResponse::Error { message } => Err(message.clone()),
            _ => Ok(()),
        };
    }

    match response {
        ControlResponse::Applied {
            applied_at_nanos,
            rule_count,
            leaf_count,
            leaves_retained,
            leaves_prospective,
        } => {
            println!("applied: {rule_count} rule(s), {leaf_count} temporal leaf/leaves");
            // The boundary: events stamped at or after this were decided under the
            // new set. Same clock and sequence as every event's `recorded_at_nanos`.
            println!("  in effect from: {applied_at_nanos}ns");
            if *leaf_count > 0 {
                println!("  {leaves_retained} kept their accumulated history");
                if *leaves_prospective > 0 {
                    // §9.2's warm-up consequence is the surprising half of
                    // prospective installs, so it is stated at the moment it
                    // becomes true rather than left for the operator to recall.
                    println!(
                        "  {leaves_prospective} start with an empty window — a new or edited \
                         temporal\n    rule does not fully bite until its window has elapsed"
                    );
                }
            }
            Ok(())
        }
        ControlResponse::Status {
            rule_count,
            leaf_count,
            incremental_leaves,
            decision_kinds,
            partition_key,
            log_offset,
            control_uids,
        } => {
            if *rule_count == 0 {
                println!("no policy set installed");
            } else {
                println!("{rule_count} rule(s), {leaf_count} temporal leaf/leaves");
                println!("  incremental leaves: {incremental_leaves}/{leaf_count}");
                println!("  decision kinds:     {}", decision_kinds.join(", "));
                // Whether the stream could be partitioned is a property of the
                // schema, and an operator cannot infer it from the policy — so it
                // is reported, including the "no" case and its reason.
                if partition_key.is_empty() {
                    println!(
                        "  partition key:      none (schema declares no universal \
                         symmetric pin — single instance)"
                    );
                } else {
                    println!("  partition key:      {}", partition_key.join(", "));
                }
            }
            println!("  events appended:    {log_offset}");
            println!("  control uids:       {control_uids:?}");
            Ok(())
        }
        ControlResponse::Batched {
            minted,
            applied_at_nanos,
        } => {
            println!("batch applied in effect from: {applied_at_nanos}ns");
            if !minted.is_empty() {
                println!("  minted policy id(s): {minted:?}");
            }
            Ok(())
        }
        ControlResponse::PolicyList {
            policies,
            next_token,
        } => {
            for p in policies {
                println!("{}  created {}  updated {}", p.id, p.created, p.updated);
            }
            if let Some(after) = next_token {
                println!("  (more — resume with --after {after})");
            }
            Ok(())
        }
        ControlResponse::Policy { source } => {
            print!("{source}");
            Ok(())
        }
        ControlResponse::Schema {
            action_schema,
            event_schema,
        } => {
            println!("# action schema");
            print!("{action_schema}");
            println!("\n# event schema");
            match event_schema {
                Some(src) => print!("{src}"),
                None => println!("(default)"),
            }
            Ok(())
        }
        ControlResponse::Checkpointed { up_to_offset } => {
            println!("checkpointed through offset {up_to_offset}");
            Ok(())
        }
        ControlResponse::Error { message } => Err(message.clone()),
    }
}

/// Print a data response.
///
/// A `Deny` exits non-zero, as does an error: the caller of `submit` is asking
/// whether an action is permitted, and a shell user piping this into `&&` means
/// "proceed if allowed". Exiting 0 on a deny would invert that.
fn report_data(cli: &Cli, response: &DataResponse) -> Result<(), String> {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(response).map_err(|e| e.to_string())?
        );
        return match response {
            DataResponse::Error { message } => Err(message.clone()),
            DataResponse::Decision { allowed: false, .. } => Err("deny".to_string()),
            _ => Ok(()),
        };
    }

    match response {
        DataResponse::Decision {
            allowed,
            reason,
            errors,
            recorded_at_nanos,
        } => {
            println!("{}", if *allowed { "ALLOW" } else { "DENY" });
            println!("  recorded at: {recorded_at_nanos}ns");
            if !reason.is_empty() {
                println!("  determined by: {}", reason.join(", "));
            }
            for e in errors {
                println!("  error: {e}");
            }
            if *allowed {
                Ok(())
            } else {
                Err("deny".to_string())
            }
        }
        DataResponse::Recorded { recorded_at_nanos } => {
            println!("recorded at {recorded_at_nanos}ns");
            Ok(())
        }
        DataResponse::Pong { version } => {
            println!("pong (server {version})");
            Ok(())
        }
        DataResponse::Error { message } => Err(message.clone()),
    }
}
