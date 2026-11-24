# Dogwood Local Engine

A durable, incremental temporal engine for [Dogwood](https://github.com/dogwood-policy/dogwood)
policies. The engine observes a stream of events, decides each request against
the events that came before it, and stores its state on disk so that after a
restart it resumes with the history it had already seen.

A Dogwood policy can refer to past actions and their outcomes: permit a read
only if the same user logged in within the last hour, permit a push only if
the tests passed and none have failed since. Deciding such a policy means
accounting for every event, ordering concurrent submissions, and keeping the
history across crashes. This crate provides an engine that does so and that is
built to be embedded as a library in the harness that mediates the agent's
tool calls. Policies
are parsed and type-checked by the `dogwood-language` crate, whose interpreter
defines the language's semantics. This crate implements that crate's
`TemporalEngine` trait, so the two work together and agree on every verdict.

## Install

To use the engine, add it and the language crate to a project:

```toml
[dependencies]
dogwood-local-engine = "1.2"
dogwood-language = "1.1"
```

The language crate is needed alongside the engine because it defines the
policy and schema types and the `Event` type that the engine consumes.

## Getting started

This section walks through one complete use of the engine: a policy, the
schema it is written against, the events of a short session and the verdicts
the engine returns for them, and the Rust program that opens a store, installs
the policy, and submits those events. It then shows that a restart keeps the
history. The example is `read_after_login` from the Dogwood language
repository: permit a `Read` only if the same user logged in within the last
hour.

### The policy

```text
@id("allow_login")
permit (principal, action == Drupe::Action::"Login", resource);

@id("read_after_login")
permit (
    principal,
    action == Drupe::Action::"Read",
    resource
)
when temporal {
    formerly within 1h Drupe::Action::"Login"::response{ input.user: context.input.user }
};
```

The `when temporal` clause is evaluated against the event history. It holds
when a `Login` response occurred in the last hour whose `input.user` equals the
`input.user` of the current request. That correlation is what makes the policy
say "the same user" rather than "anyone".

### The schema

The policy and the events share a vocabulary, declared in a schema. For each
action the schema names the principals that can take it, the resources it acts
on, and the fields of its request input.

```text
namespace Drupe {
  type LoginInput = { user: String };
  type ReadInput = { user: String };
  entity Gateway;
  entity OAuthUser = { id: String } tags String;
  action "Login" appliesTo {
    principal: [OAuthUser],
    resource: [Gateway],
    context: { input: LoginInput }
  };
  action "Read" appliesTo {
    principal: [OAuthUser],
    resource: [Gateway],
    context: { input: ReadInput }
  };
}
```

### The events

An event is a record of one step of a tool call. A call produces a `request`
event when it is made and a `response` event when it returns. The engine
issues a verdict for every request event; response events are recorded as
history and get no verdict. Here is one session of four events, with the
verdict the engine returns for each request:

```text
@0     Login::request   { user: "alice" }   -> ALLOW   // allow_login
@5     Login::response  { user: "alice" }
@10    Read::request    { user: "alice" }   -> ALLOW   // logged in 5s ago
@7200  Read::request    { user: "alice" }   -> DENY    // login is 2h old
```

At `@0` alice logs in; `allow_login` permits the request. At `@5` the login
returns and the engine records the response. At `@10` alice reads.
A `Login` response for the same user is five seconds behind the request, well
inside the hour, so the read is allowed. At `@7200` alice reads again. The only
login is two hours old, the window has passed, and the read is denied.

### Open, install, submit

The following program opens a store, installs the policy, and submits the
first three events.

```rust
use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{DurableError, DurableTemporalEngine, Outcome};

const POLICY: &str = r#"
@id("allow_login")
permit (principal, action == Drupe::Action::"Login", resource);

@id("read_after_login")
permit (principal, action == Drupe::Action::"Read", resource)
when temporal {
    formerly within 1h Drupe::Action::"Login"::response{ input.user: context.input.user }
};
"#;

const SCHEMA: &str = r#"
namespace Drupe {
  type LoginInput = { user: String };
  type ReadInput = { user: String };
  entity Gateway;
  entity OAuthUser = { id: String } tags String;
  action "Login" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: LoginInput }
  };
  action "Read" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ReadInput }
  };
}
"#;

/// One of alice's events. The engine assigns the timestamp, so the
/// builder carries none. `field` sets the logged `input.user` that the
/// event pattern in the policy matches; `request_context` sets the
/// `context.input.user` the policy compares it against.
fn alice(action: &str, kind: &str) -> EventBuilder {
    Event::builder(action, kind)
        .principal("Drupe::OAuthUser::\"alice\"")
        .resource("Drupe::Gateway::\"gw1\"")
        .field("input", "user", Value::String("alice".to_string()))
        .request_context("input", "user", Value::String("alice".to_string()))
}

# fn main() -> Result<(), DurableError> {
# let path = std::env::temp_dir().join(format!("dogwood-readme-{}", std::process::id()));
// Open the store at `path`, creating it if absent. Snapshot the monitor
// state every 1000 events.
let mut engine = DurableTemporalEngine::open(&path, 1000)?;

// Install the policy set against its schema. The event schema and macro
// library are left at their defaults.
engine.install(POLICY, SCHEMA, None, None)?;

// alice logs in. The request is a decision point; the response is history.
engine.submit(alice("Drupe::Action::Login", "request"))?;
engine.submit(alice("Drupe::Action::Login", "response"))?;

// alice reads within the hour.
let read = engine.submit(alice("Drupe::Action::Read", "request"))?;
match read.outcome {
    Outcome::Decision(verdict) => assert!(verdict.allowed()),
    Outcome::Recorded => unreachable!("a request event always gets a verdict"),
}
# drop(engine);
# std::fs::remove_file(&path).ok();
# Ok(())
# }
```

A few things to know about `submit`:

- The engine assigns the event's timestamp when it appends the event to its
  log. Callers never supply one. The assigned time is returned in
  `Submitted::ts`, in nanoseconds since the Unix epoch, and it is the instant
  every window is measured against.
- A `request` event returns `Outcome::Decision` carrying the verdict. A
  `response` event returns `Outcome::Recorded`.
- `submit` takes `&mut self`. To share one engine between threads, put it
  behind a mutex; the engine orders submissions in the order it receives them.
- The second argument to `open` is the snapshot interval: how many events the
  engine appends between snapshots of its monitor state. `0` disables periodic
  snapshots and leaves checkpoints to the caller.

### Restart and recover

Opening the same path again recovers the installed policy set and the monitor
state. The login is still in the window, so the next read is still allowed.

```rust,no_run
# use dogwood_local_engine::{DurableError, DurableTemporalEngine};
# fn main() -> Result<(), DurableError> {
# let path = "store.redb";
let mut engine = DurableTemporalEngine::open(path, 1000)?;
assert!(engine.has_policy());
# Ok(())
# }
```

## How the engine processes an event

Each `submit` takes three steps: linearize, persist, evaluate.

The engine supports concurrent submissions and linearizes them through a
lock, admitting one at a time. Under that lock it stamps the event with the
current time, clamped to stay strictly after the previous event even if the
system clock steps back, and appends it to its log. The append position fixes
the event's place in the history. The engine syncs the append to disk before
it evaluates anything, so an event that has a verdict is an event the log
holds. Then, still under the lock, it evaluates the policies whose scope
covers the request and returns the verdict.

Evaluation is incremental. Each temporal condition keeps only the history
inside its own window, updated as events arrive, rather than rescanning the
log on every request. State stays bounded for bounded windows.

On restart the engine loads its latest snapshot and replays the log records
after it. Events older than the snapshot are pruned. An acknowledged submit is
never lost to a crash; a store the engine cannot recover is refused rather
than opened with part of its history.

## Policy updates

The policy set can change while the engine is running. `install` replaces the
whole set from source; `batch` applies a list of `Verb`s (such as add, update,
delete, and set the action schema) as one change and returns a `PolicyToken`
for each policy it adds; `list` and `get_policy` read the set back.

A newly added policy starts with an empty history. It judges the requests after
its installation and sees only the events after it, because the engine prunes
events once a snapshot has captured what the current policies need, and a
later policy may ask about information nothing recorded. A policy left
unchanged by an update keeps the history it had accumulated.

A policy update is a record in the same log as the events. It takes its place
in the order under the same lock and is synced in one transaction, so every
request behind it sees the whole updated set and none sees a mixture of old
and new. On recovery the engine replays updates in log order with the events.
A change that fails to parse, lower, or validate writes nothing.

## Information providers

A policy can call an information provider to get a fact that is not in the
request, such as whether a piece of text matches a pattern, or what another
system says about it. The call looks like a function call in a `when` clause.
The engine computes the answer before each decision. The
[Dogwood guide](https://dogwood-policy.github.io/dogwood/guide/05-information-providers.html)
describes the language side.

### Declaring providers

Providers are declared in a JSON document passed to `install_with_providers`.
Each entry gives the provider's name, its argument types, its output type,
and usually a script that computes the answer.

```rust
use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{DurableError, DurableTemporalEngine, Outcome};

const PROVIDERS: &str = r##"{
  "availableProviders": {
    "Strings::Matches": {
      "argumentTypes": [{ "paramType": "string" }, { "paramType": "string" }],
      "outputType": {
        "paramType": "record",
        "fields": { "matched": { "paramType": "bool" } },
        "required": ["matched"]
      },
      "implementation": {
        "kind": "rhai",
        "script": "fn evaluate(text, pattern) { if type_of(text) == \"()\" { return #{ matched: false }; } #{ matched: regex_is_match(pattern, text) } }"
      }
    }
  }
}"##;

const POLICY: &str = r#"
permit (principal, action == Action::"Read", resource)
when { Strings::Matches(context.input.document, "^[A-Z]+$").matched == true };
"#;

const SCHEMA: &str = r#"
entity User;
entity Doc;
action Read appliesTo {
    principal: User, resource: Doc, context: { input: { document: String } }
};
"#;

fn read(document: &str) -> EventBuilder {
    Event::builder("Action::Read", "request")
        .principal("User::\"alice\"")
        .resource("Doc::\"d\"")
        .field("input", "document", Value::String(document.to_string()))
        .request_context("input", "document", Value::String(document.to_string()))
}

# fn main() -> Result<(), DurableError> {
# let path = std::env::temp_dir().join(format!("dogwood-readme-providers-{}", std::process::id()));
let mut engine = DurableTemporalEngine::open(&path, 1000)?;
engine.install_with_providers(POLICY, SCHEMA, None, None, Some(PROVIDERS))?;

let upper = engine.submit(read("ABC"))?;
let lower = engine.submit(read("abc"))?;
match (upper.outcome, lower.outcome) {
    (Outcome::Decision(upper), Outcome::Decision(lower)) => {
        assert!(upper.allowed());
        assert!(!lower.allowed());
    }
    _ => unreachable!("a request event always gets a verdict"),
}
# drop(engine);
# std::fs::remove_file(&path).ok();
# Ok(())
# }
```

The declarations are part of the store's configuration, like the event schema
and the macro library. They are saved with the first install and restored when
the store is reopened. After that they are fixed: a later install with
different declarations is rejected.

The script text must be in the JSON itself. A script named by file, with
`"scriptFile"` in place of `"script"`, is rejected at install.

### Answering a provider in your own code

A script runs in a sandbox and cannot reach the network or the file system.
For a provider whose answer comes from somewhere else, declare it with no
`implementation` and give the engine a `ProviderResolver`.

```rust,no_run
use std::collections::BTreeMap;
use std::sync::Arc;

use dogwood_language::{ProviderRequest, ProviderResolver, Value};
use dogwood_local_engine::{DurableError, DurableTemporalEngine};

struct Checks;

impl ProviderResolver for Checks {
    fn resolve(&self, request: ProviderRequest<'_>) -> Option<Result<Value, String>> {
        if request.key() != "Remote::Check" {
            // Not handled here: the provider's own script runs.
            return None;
        }
        let safe = lookup(request.args);
        Some(Ok(Value::Object(BTreeMap::from([(
            "safe".to_string(),
            Value::Bool(safe),
        )]))))
    }
}

/// Your own code: a service call, a database read, a model.
fn lookup(_args: &[Value]) -> bool {
    true
}

# fn main() -> Result<(), DurableError> {
let mut engine = DurableTemporalEngine::open("store.redb", 1000)?;
engine.set_provider_resolver(Arc::new(Checks));
# Ok(())
# }
```

A few things to know about the resolver:

- It is not stored. Set it after every `open`. Until it is set, a provider
  with no implementation has no answer, and decisions are denied with an error
  in the verdict's diagnostics.
- It is asked first for every provider call, including providers that have a
  script. Returning `None` lets the script run. Returning an answer replaces
  the script.
- A panic in the resolver is reported as a provider error, so the decision is
  a deny.
- Every provider call in the policy set runs on every decision, inside
  `submit`. A slow resolver delays every caller.

## What the embedding application must still do

The engine issues verdicts. It does not enforce them, and it cannot check that
the events it is shown are true. The component that embeds it, the harness
that mediates tool calls, is responsible for:

- submitting every event the policies depend on;
- authenticating where each event came from and that its fields are accurate;
- running an action only when the verdict is allow;
- restricting access to the store files and to the engine's memory;
- controlling who may change the policy set, and reporting a failed change;
- keeping its own audit log, since the engine's log is pruned;
- protecting the host clock the engine reads.

The repository [README](https://github.com/dogwood-policy/dogwood-local-engine#readme)
explains each of these in detail.

## Where next

- The [Dogwood guide](https://dogwood-policy.github.io/dogwood/): the
  [language](https://dogwood-policy.github.io/dogwood/guide/01-getting-started.html),
  [temporal expressions](https://dogwood-policy.github.io/dogwood/guide/04-temporal-expressions.html),
  and the [CLI](https://dogwood-policy.github.io/dogwood/guide/12-cli.html) for
  validating and replaying policies before installing them.
- `dogwood-server`, in the same repository, is a reference demo that puts the
  engine behind Unix sockets with a separate control plane for policy changes.

## License

Apache-2.0. See [LICENSE](https://github.com/dogwood-policy/dogwood-local-engine/blob/main/LICENSE)
and [NOTICE](https://github.com/dogwood-policy/dogwood-local-engine/blob/main/NOTICE).
