//! Trace correlation — groups WAL events by trace_id for tree-view rendering.

use std::collections::HashMap;

/// Index of timeline entries grouped by trace_id.
pub(crate) struct TraceIndex {
    /// trace_id -> list of timeline indices (in order of appearance).
    traces: HashMap<String, Vec<usize>>,
}

impl TraceIndex {
    pub(crate) fn new() -> Self {
        Self {
            traces: HashMap::new(),
        }
    }

    /// Record a timeline entry's trace_id and its index.
    pub(crate) fn record(&mut self, trace_id: &str, timeline_idx: usize) {
        self.traces
            .entry(trace_id.to_string())
            .or_default()
            .push(timeline_idx);
    }

    /// Get all timeline indices for a given trace_id.
    pub(crate) fn get(&self, trace_id: &str) -> Option<&[usize]> {
        self.traces.get(trace_id).map(|v| v.as_slice())
    }
}
