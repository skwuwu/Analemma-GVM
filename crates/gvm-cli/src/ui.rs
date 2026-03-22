/// ANSI color codes for terminal output.
pub const GREEN: &str = "\x1b[92m";
pub const YELLOW: &str = "\x1b[93m";
pub const RED: &str = "\x1b[91m";
pub const CYAN: &str = "\x1b[96m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RESET: &str = "\x1b[0m";

const WIDTH: usize = 72;

/// Print a single dry-run check result.
#[allow(clippy::too_many_arguments)]
pub fn print_check_result(
    operation: &str,
    service: &str,
    tier: &str,
    sensitivity: &str,
    host: &str,
    method: &str,
    decision: &str,
    engine_ms: f64,
    event_id: Option<&str>,
    next_action: Option<&str>,
) {
    println!();
    println!(
        "{BOLD}Analemma-GVM — Dry-Run Policy Check{RESET}"
    );
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!();
    println!("  {DIM}Operation:{RESET}    {BOLD}{}{RESET}", operation);
    println!("  {DIM}Resource:{RESET}     {} (tier={}, sensitivity={})", service, tier, sensitivity);
    println!("  {DIM}Target:{RESET}       {} {}", method, host);
    println!();

    let (icon, color) = match decision {
        d if d.contains("Allow") => ("\u{2713}", GREEN),
        d if d.contains("Delay") => ("\u{23f1}", YELLOW),
        d if d.contains("Approval") => ("\u{1f6e1}\u{fe0f}", RED),
        _ => ("\u{2717}", RED),
    };

    println!(
        "  {BOLD}Decision:{RESET}    {color}{icon} {}{RESET}",
        decision
    );
    println!("  {DIM}Engine time:{RESET}  {:.1}ms", engine_ms);

    if let Some(id) = event_id {
        println!("  {DIM}Event ID:{RESET}    {}", id);
    }
    if let Some(action) = next_action {
        println!("  {DIM}Next action:{RESET} {}", action);
    }

    println!();
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!(
        "  {DIM}This was a dry-run. No API calls were made. No events were recorded.{RESET}"
    );
    println!("{}", "\u{2501}".repeat(WIDTH));
    println!();
}
