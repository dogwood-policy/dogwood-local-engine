use dogwood_language::{Event, Value};
use dogwood_local_engine::{PolicyId, PolicyToken, Record};

const TEXT_SIZES: [usize; 3] = [32, 1024, 65_536];

pub struct CodecCase {
    pub name: String,
    pub record: Record,
    pub encoded: Vec<u8>,
}

impl CodecCase {
    fn new(name: impl Into<String>, record: Record) -> Self {
        let encoded = record.encode();
        Self {
            name: name.into(),
            record,
            encoded,
        }
    }
}

fn text(size: usize, marker: char) -> String {
    std::iter::repeat_n(marker, size).collect()
}

fn event_record() -> Record {
    Record::Event(
        Event::builder("Ns::Action::Read", "request")
            .timestamp(1_700_000_000_123_456_789)
            .principal("Ns::User::\"alice\"")
            .resource("Ns::Document::\"report\"")
            .field("input", "body", Value::String(text(1024, 'e')))
            .request_context("input", "body", Value::String(text(1024, 'c')))
            .build(),
    )
}

pub fn cases() -> Vec<CodecCase> {
    let mut cases = vec![
        CodecCase::new("event/2x1KiB", event_record()),
        CodecCase::new(
            "delete",
            Record::Delete {
                ts: i64::MAX,
                id: PolicyId(u64::MAX),
            },
        ),
        CodecCase::new(
            "reset",
            Record::Reset {
                ts: i64::MIN,
                id: PolicyId(u64::MAX),
            },
        ),
        CodecCase::new("delete_all", Record::DeleteAll { ts: 17 }),
        CodecCase::new("reset_all", Record::ResetAll { ts: 18 }),
    ];

    for size in TEXT_SIZES {
        cases.push(CodecCase::new(
            format!("add/{size}B"),
            Record::Add {
                ts: 11,
                id: PolicyId(u64::MAX),
                token: PolicyToken(text(size, 't')),
                statement: text(size, 's'),
            },
        ));
        cases.push(CodecCase::new(
            format!("update/{size}B"),
            Record::Update {
                ts: 12,
                id: PolicyId(u64::MAX),
                statement: text(size, 'u'),
            },
        ));
        cases.push(CodecCase::new(
            format!("set_action_schema/{size}B"),
            Record::SetActionSchema {
                ts: 13,
                action_schema: text(size, 'a'),
            },
        ));
        cases.push(CodecCase::new(
            format!("append_action_schema/{size}B"),
            Record::AppendActionSchema {
                ts: 14,
                fragment: text(size, 'f'),
            },
        ));
    }
    cases
}
