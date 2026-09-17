#![cfg(not(feature = "fault-injection"))]

use std::time::Duration;

use dogwood_local_engine::{DurableConfig, WallClock};

#[test]
fn durable_config_remains_externally_constructible() {
    let config = DurableConfig {
        snapshot_interval: 17,
        clock: Box::new(WallClock),
        max_future_skew: Duration::from_secs(23),
    };

    assert_eq!(config.snapshot_interval, 17);
    assert_eq!(config.max_future_skew, Duration::from_secs(23));
}
