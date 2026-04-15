//! TUI dashboard for `gvm watch --output tui`.
//!
//! Provides a real-time terminal dashboard for agent debugging with:
//! - Live event timeline (scrollable, color-coded by decision)
//! - Anomaly detection panel (burst, loop, unknown host warnings)
//! - Policy decision distribution (Allow/Delay/Deny bar chart)
//! - Host stats and LLM usage panels
//! - Trace correlation view (group events by trace_id)

mod trace;
mod ui;

use std::collections::VecDeque;
use std::io;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{backend::CrosstermBackend, widgets::TableState, Terminal};

use crate::watch::{AnomalyDetector, SessionStats};
use trace::TraceIndex;

/// Maximum number of timeline entries to keep in memory.
const MAX_TIMELINE_ENTRIES: usize = 500;

/// A single entry in the live event timeline.
#[derive(Clone)]
pub(crate) struct TimelineEntry {
    pub(crate) index: usize,
    pub(crate) time_short: String,
    pub(crate) method: String,
    pub(crate) host: String,
    pub(crate) path: String,
    pub(crate) decision: String,
    pub(crate) status_code: Option<u16>,
    pub(crate) total_tokens: Option<u64>,
    pub(crate) trace_id: String,
}

/// Full TUI application state.
pub(crate) struct TuiState {
    pub(crate) stats: SessionStats,
    pub(crate) anomaly: AnomalyDetector,
    pub(crate) timeline: VecDeque<TimelineEntry>,
    pub(crate) trace_index: TraceIndex,
    pub(crate) trace_view: Option<String>,
    pub(crate) agent_id: String,
    entry_counter: usize,
}

impl TuiState {
    pub(crate) fn new(agent_id: String) -> Self {
        Self {
            stats: SessionStats::new(),
            anomaly: AnomalyDetector::new(),
            timeline: VecDeque::with_capacity(MAX_TIMELINE_ENTRIES),
            trace_index: TraceIndex::new(),
            trace_view: None,
            agent_id,
            entry_counter: 0,
        }
    }

    /// Process a raw WAL event: update stats, anomaly detector, timeline, and trace index.
    pub(crate) fn process_event(&mut self, event: &serde_json::Value) {
        self.stats.record_event(event);

        let method = event
            .pointer("/transport/method")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let host = event
            .pointer("/transport/host")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let path = event
            .pointer("/transport/path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let default_caution = event
            .get("default_caution")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        self.anomaly
            .record_request(&method, &host, &path, default_caution);

        // Skip state-machine duplicate entries (dedup by event_id already in SessionStats).
        // But timeline always shows the latest state for an event_id.
        let event_id = event
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // Check if this event_id already exists in timeline (state transition update)
        if let Some(existing) = self
            .timeline
            .iter_mut()
            .rev()
            .find(|e| e.trace_id == event_id)
        {
            // Update status code if now available
            if let Some(code) = event
                .pointer("/transport/status_code")
                .and_then(|v| v.as_u64())
            {
                existing.status_code = Some(code as u16);
            }
            return;
        }

        let timestamp = event
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let time_short = if timestamp.len() >= 19 {
            timestamp[11..19].to_string()
        } else {
            timestamp.to_string()
        };

        let decision = event
            .get("decision")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let status_code = event
            .pointer("/transport/status_code")
            .and_then(|v| v.as_u64())
            .map(|c| c as u16);

        let total_tokens = event
            .pointer("/llm_trace/usage/total_tokens")
            .and_then(|v| v.as_u64())
            .or_else(|| {
                let p = event
                    .pointer("/llm_trace/usage/prompt_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let c = event
                    .pointer("/llm_trace/usage/completion_tokens")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                if p > 0 || c > 0 {
                    Some(p + c)
                } else {
                    None
                }
            });

        let trace_id = event
            .get("trace_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let idx = self.entry_counter;
        self.entry_counter += 1;

        let entry = TimelineEntry {
            index: idx,
            time_short,
            method,
            host,
            path,
            decision,
            status_code,
            total_tokens,
            trace_id: trace_id.clone(),
        };

        if !trace_id.is_empty() {
            self.trace_index.record(&trace_id, idx);
        }

        self.timeline.push_back(entry);
        if self.timeline.len() > MAX_TIMELINE_ENTRIES {
            self.timeline.pop_front();
        }
    }

    pub(crate) fn requests_per_sec(&self) -> f64 {
        let elapsed = self.stats.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.stats.total_requests as f64 / elapsed
        } else {
            0.0
        }
    }
}

/// Run the TUI dashboard. Blocks until the agent exits or the user presses 'q'.
///
/// `event_rx` receives batches of parsed WAL events from a background tokio task.
/// `agent_done_rx` signals when the agent process has exited.
pub(crate) async fn run_tui(
    agent_id: &str,
    wal_path: &str,
    wal_start_offset: u64,
    mut agent_done_rx: tokio::sync::watch::Receiver<bool>,
) -> Result<TuiState> {
    // Setup terminal
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;

    let mut state = TuiState::new(agent_id.to_string());
    let mut table_state = TableState::default();
    let mut wal_offset = wal_start_offset;
    let mut agent_exited = false;

    // Tick interval for rendering + WAL polling
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));

    loop {
        // Render
        terminal.draw(|frame| {
            ui::render(frame, &state, &mut table_state);
        })?;

        // Handle events with timeout
        tokio::select! {
            _ = tick.tick() => {
                // Poll WAL for new events
                if let Ok((events, new_offset)) =
                    crate::watch::read_wal_from_offset(wal_path, wal_offset)
                {
                    wal_offset = new_offset;
                    for (event, _raw) in &events {
                        state.process_event(event);
                    }
                    // Auto-scroll to bottom when new events arrive
                    if !events.is_empty() && state.trace_view.is_none() {
                        table_state.select(Some(0)); // newest is at top (reversed)
                    }
                }

                // Check if agent exited
                if agent_done_rx.has_changed().unwrap_or(false) {
                    if *agent_done_rx.borrow_and_update() {
                        agent_exited = true;
                    }
                }

                // Handle crossterm events (non-blocking)
                while event::poll(std::time::Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind != KeyEventKind::Press {
                            continue;
                        }
                        match key.code {
                            KeyCode::Char('q') => {
                                cleanup_terminal()?;
                                return Ok(state);
                            }
                            KeyCode::Up => {
                                let i = table_state.selected().unwrap_or(0);
                                let max = state.timeline.len().saturating_sub(1);
                                table_state.select(Some((i + 1).min(max)));
                            }
                            KeyCode::Down => {
                                let i = table_state.selected().unwrap_or(0);
                                table_state.select(Some(i.saturating_sub(1)));
                            }
                            KeyCode::Char('t') => {
                                if state.trace_view.is_some() {
                                    state.trace_view = None;
                                } else {
                                    // Pick trace_id from currently selected timeline entry
                                    if let Some(selected) = table_state.selected() {
                                        let entries: Vec<_> = state.timeline.iter().rev().collect();
                                        if let Some(entry) = entries.get(selected) {
                                            if !entry.trace_id.is_empty() {
                                                state.trace_view = Some(entry.trace_id.clone());
                                            }
                                        }
                                    }
                                }
                            }
                            KeyCode::Esc => {
                                state.trace_view = None;
                            }
                            _ => {}
                        }
                    }
                }
            }
            Ok(()) = agent_done_rx.changed() => {
                if *agent_done_rx.borrow() {
                    agent_exited = true;
                }
            }
        }

        // After agent exits, do one final WAL sweep, render, then wait for 'q'
        if agent_exited {
            // Final WAL sweep
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            if let Ok((events, _)) = crate::watch::read_wal_from_offset(wal_path, wal_offset) {
                for (event, _) in &events {
                    state.process_event(event);
                }
            }

            // Show "Agent exited" and wait for quit
            loop {
                terminal.draw(|frame| {
                    ui::render(frame, &state, &mut table_state);
                })?;

                if event::poll(std::time::Duration::from_millis(250))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind == KeyEventKind::Press {
                            match key.code {
                                KeyCode::Char('q') | KeyCode::Esc => {
                                    cleanup_terminal()?;
                                    return Ok(state);
                                }
                                KeyCode::Up => {
                                    let i = table_state.selected().unwrap_or(0);
                                    let max = state.timeline.len().saturating_sub(1);
                                    table_state.select(Some((i + 1).min(max)));
                                }
                                KeyCode::Down => {
                                    let i = table_state.selected().unwrap_or(0);
                                    table_state.select(Some(i.saturating_sub(1)));
                                }
                                KeyCode::Char('t') => {
                                    if state.trace_view.is_some() {
                                        state.trace_view = None;
                                    } else if let Some(selected) = table_state.selected() {
                                        let entries: Vec<_> = state.timeline.iter().rev().collect();
                                        if let Some(entry) = entries.get(selected) {
                                            if !entry.trace_id.is_empty() {
                                                state.trace_view = Some(entry.trace_id.clone());
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
}

fn cleanup_terminal() -> Result<()> {
    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
