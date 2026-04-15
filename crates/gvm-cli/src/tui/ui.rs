//! TUI rendering — layout and widget construction for the watch dashboard.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Row, Table, TableState},
    Frame,
};

use super::{TimelineEntry, TuiState};
use crate::watch::format_duration;

/// Render the full dashboard to a frame.
pub(crate) fn render(frame: &mut Frame, state: &TuiState, table_state: &mut TableState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),   // Header
            Constraint::Min(6),      // Top panels (anomaly + decisions)
            Constraint::Min(4),      // Mid panels (hosts + LLM)
            Constraint::Fill(1),     // Timeline (fills remaining)
            Constraint::Length(1),   // Footer
        ])
        .split(frame.area());

    render_header(frame, chunks[0], state);
    render_top_panels(frame, chunks[1], state);
    render_mid_panels(frame, chunks[2], state);
    render_timeline(frame, chunks[3], state, table_state);
    render_footer(frame, chunks[4], state);
}

fn render_header(frame: &mut Frame, area: Rect, state: &TuiState) {
    let elapsed = format_duration(state.stats.start_time.elapsed());
    let text = Line::from(vec![
        Span::styled(" Agent Runtime Watch ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("  "),
        Span::styled(&state.agent_id, Style::default().fg(Color::White)),
        Span::raw("    "),
        Span::styled(elapsed, Style::default().fg(Color::DarkGray)),
        Span::raw("    "),
        Span::styled(
            format!("{} reqs", state.stats.total_requests),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            format!("{:.1} req/s", state.requests_per_sec()),
            Style::default().fg(Color::DarkGray),
        ),
    ]);
    let block = Block::default().borders(Borders::ALL).border_style(Style::default().fg(Color::DarkGray));
    let paragraph = Paragraph::new(text).block(block);
    frame.render_widget(paragraph, area);
}

fn render_top_panels(frame: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_anomaly_panel(frame, chunks[0], state);
    render_decision_panel(frame, chunks[1], state);
}

fn render_anomaly_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .title(" Anomalies ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let warnings = state.anomaly.warnings();
    let items: Vec<ListItem> = warnings
        .iter()
        .filter(|w| !w.starts_with("unknown:"))
        .rev()
        .take(area.height.saturating_sub(2) as usize)
        .map(|w| {
            let style = if w.contains("Burst") || w.contains("Loop") {
                Style::default().fg(Color::Red)
            } else {
                Style::default().fg(Color::Yellow)
            };
            ListItem::new(Line::from(Span::styled(format!(" \u{26a0} {}", w), style)))
        })
        .collect();

    if items.is_empty() {
        let empty = Paragraph::new(Line::from(Span::styled(
            " No anomalies detected",
            Style::default().fg(Color::DarkGray),
        )))
        .block(block);
        frame.render_widget(empty, area);
    } else {
        let list = List::new(items).block(block);
        frame.render_widget(list, area);
    }
}

fn render_decision_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .title(" Policy Decisions ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let total = state.stats.total_requests.max(1) as f64;
    let allowed = *state.stats.decisions.get("Allow").unwrap_or(&0);
    let delayed = *state.stats.decisions.get("Delay").unwrap_or(&0);
    let denied = *state.stats.decisions.get("Deny").unwrap_or(&0);

    let bar_width = area.width.saturating_sub(20) as f64;

    let lines = vec![
        decision_bar_line("Allow", allowed, total, bar_width, Color::Green),
        decision_bar_line("Delay", delayed, total, bar_width, Color::Yellow),
        decision_bar_line("Deny ", denied, total, bar_width, Color::Red),
    ];

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

fn decision_bar_line(label: &str, count: u64, total: f64, bar_width: f64, color: Color) -> Line<'static> {
    let pct = count as f64 / total;
    let filled = (pct * bar_width) as usize;
    let empty = bar_width as usize - filled;
    Line::from(vec![
        Span::styled(format!(" {} ", label), Style::default().fg(color).add_modifier(Modifier::BOLD)),
        Span::styled("\u{2588}".repeat(filled), Style::default().fg(color)),
        Span::styled("\u{2591}".repeat(empty), Style::default().fg(Color::DarkGray)),
        Span::styled(format!(" {}", count), Style::default().fg(Color::White)),
    ])
}

fn render_mid_panels(frame: &mut Frame, area: Rect, state: &TuiState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_host_panel(frame, chunks[0], state);
    render_llm_panel(frame, chunks[1], state);
}

fn render_host_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .title(" Host Stats ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let mut sorted_hosts: Vec<_> = state.stats.hosts.iter().collect();
    sorted_hosts.sort_by(|a, b| b.1.cmp(a.1));

    let max_rows = area.height.saturating_sub(2) as usize;
    let items: Vec<ListItem> = sorted_hosts
        .iter()
        .take(max_rows)
        .map(|(host, count)| {
            ListItem::new(Line::from(vec![
                Span::styled(format!(" {:<28}", truncate(host, 28)), Style::default().fg(Color::Cyan)),
                Span::styled(format!("{:>5}", count), Style::default().fg(Color::White)),
            ]))
        })
        .collect();

    let list = List::new(items).block(block);
    frame.render_widget(list, area);
}

fn render_llm_panel(frame: &mut Frame, area: Rect, state: &TuiState) {
    let block = Block::default()
        .title(" LLM Usage ")
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let stats = &state.stats;
    let mut lines = Vec::new();

    if stats.llm_calls > 0 {
        lines.push(Line::from(vec![
            Span::styled(" Tokens: ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                crate::watch::format_number(stats.total_tokens),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  Cost: ${:.4}", stats.estimated_cost),
                Style::default().fg(Color::Yellow),
            ),
        ]));
        if !stats.models_used.is_empty() {
            let models: Vec<_> = stats.models_used.iter().map(|s| s.as_str()).collect();
            lines.push(Line::from(Span::styled(
                format!(" Models: {}", models.join(", ")),
                Style::default().fg(Color::DarkGray),
            )));
        }
        if stats.thinking_count > 0 {
            lines.push(Line::from(Span::styled(
                format!(" Thinking: {} responses", stats.thinking_count),
                Style::default().fg(Color::DarkGray),
            )));
        }
    } else {
        lines.push(Line::from(Span::styled(
            " No LLM calls detected",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let paragraph = Paragraph::new(lines).block(block);
    frame.render_widget(paragraph, area);
}

fn render_timeline(frame: &mut Frame, area: Rect, state: &TuiState, table_state: &mut TableState) {
    let title = if state.trace_view.is_some() {
        let tid = state.trace_view.as_deref().unwrap_or("");
        format!(" Trace View: {} ", truncate(tid, 20))
    } else {
        " Live Event Timeline ".to_string()
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::DarkGray));

    let header = Row::new(vec![
        "TIME", "  ", "METHOD", "HOST", "PATH", "ST", "DECISION", "TOKENS",
    ])
    .style(Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD));

    let rows: Vec<Row> = if let Some(ref trace_id) = state.trace_view {
        // Trace view: show events belonging to selected trace as tree
        render_trace_rows(state, trace_id)
    } else {
        // Normal timeline: show recent events
        state
            .timeline
            .iter()
            .rev()
            .map(|entry| timeline_row(entry))
            .collect()
    };

    let widths = [
        Constraint::Length(8),  // TIME
        Constraint::Length(2),  // icon
        Constraint::Length(7),  // METHOD
        Constraint::Length(25), // HOST
        Constraint::Length(30), // PATH
        Constraint::Length(3),  // ST
        Constraint::Length(8),  // DECISION
        Constraint::Length(10), // TOKENS
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    frame.render_stateful_widget(table, area, table_state);
}

fn timeline_row(entry: &TimelineEntry) -> Row<'static> {
    let (icon, color) = match entry.decision.as_str() {
        d if d.contains("Allow") => ("\u{2713}", Color::Green),
        d if d.contains("Delay") => ("\u{23f1}", Color::Yellow),
        d if d.contains("Deny") => ("\u{2717}", Color::Red),
        _ => ("\u{2022}", Color::DarkGray),
    };

    let decision_short = if entry.decision.contains("Allow") {
        "Allow"
    } else if entry.decision.contains("Delay") {
        "Delay"
    } else if entry.decision.contains("Deny") {
        "Deny"
    } else {
        &entry.decision
    };

    let tokens = entry
        .total_tokens
        .map(|t| crate::watch::format_number(t))
        .unwrap_or_default();

    Row::new(vec![
        entry.time_short.clone(),
        icon.to_string(),
        entry.method.clone(),
        truncate(&entry.host, 25).to_string(),
        truncate(&entry.path, 30).to_string(),
        entry.status_code.map(|c| c.to_string()).unwrap_or_else(|| "---".into()),
        decision_short.to_string(),
        tokens,
    ])
    .style(Style::default().fg(color))
}

fn render_trace_rows(state: &TuiState, trace_id: &str) -> Vec<Row<'static>> {
    let indices = match state.trace_index.get(trace_id) {
        Some(idx) => idx,
        None => return vec![Row::new(vec!["No events found for this trace".to_string()])],
    };

    let mut rows = Vec::new();
    let len = indices.len();
    for (i, &idx) in indices.iter().enumerate() {
        if let Some(entry) = state.timeline.iter().find(|e| e.index == idx) {
            let prefix = if i == len - 1 { "\u{2514} " } else { "\u{251c} " };
            let (icon, color) = match entry.decision.as_str() {
                d if d.contains("Allow") => ("\u{2713}", Color::Green),
                d if d.contains("Delay") => ("\u{23f1}", Color::Yellow),
                d if d.contains("Deny") => ("\u{2717}", Color::Red),
                _ => ("\u{2022}", Color::DarkGray),
            };
            let tokens = entry
                .total_tokens
                .map(|t| crate::watch::format_number(t))
                .unwrap_or_default();

            rows.push(
                Row::new(vec![
                    entry.time_short.clone(),
                    icon.to_string(),
                    format!("{}{}", prefix, entry.method),
                    truncate(&entry.host, 25).to_string(),
                    truncate(&entry.path, 30).to_string(),
                    entry.status_code.map(|c| c.to_string()).unwrap_or_else(|| "---".into()),
                    entry.decision.clone(),
                    tokens,
                ])
                .style(Style::default().fg(color)),
            );
        }
    }
    rows
}

fn render_footer(frame: &mut Frame, area: Rect, state: &TuiState) {
    let trace_hint = if state.trace_view.is_some() {
        "[Esc] back"
    } else {
        "[t] trace view"
    };
    let line = Line::from(vec![
        Span::styled(" [q] ", Style::default().fg(Color::DarkGray)),
        Span::styled("quit", Style::default().fg(Color::White)),
        Span::styled("  [\u{2191}\u{2193}] ", Style::default().fg(Color::DarkGray)),
        Span::styled("scroll", Style::default().fg(Color::White)),
        Span::styled(format!("  {}", trace_hint), Style::default().fg(Color::DarkGray)),
    ]);
    let paragraph = Paragraph::new(line);
    frame.render_widget(paragraph, area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}...", &s[..max.saturating_sub(3)])
    } else {
        s.to_string()
    }
}
