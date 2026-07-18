use crate::authority::Authority;
use crate::clock::{Clock, SystemClock};
use crate::model::short_id;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Paragraph};
use std::io;
use std::time::Duration;

pub fn run(authority: Box<dyn Authority>, repo_id: String) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_loop(&mut terminal, authority.as_ref(), &repo_id);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    authority: &dyn Authority,
    repo_id: &str,
) -> Result<()> {
    let clock = SystemClock;
    loop {
        let now = clock.now_ms();
        let status = authority.status(repo_id, now);
        terminal.draw(|frame| {
            let areas = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(8), Constraint::Length(3)])
                .split(frame.area());
            frame.render_widget(
                Paragraph::new("PANDO · working-tree continuity")
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL)),
                areas[0],
            );
            let body = match &status {
                Ok(status) => {
                    let lease = status.lease.as_ref()
                        .map(|lease| format!("{} · generation {} · {}ms remaining", lease.holder, lease.generation, lease.expires_at_ms.saturating_sub(now)))
                        .unwrap_or_else(|| "free".into());
                    let head = status.head.as_deref().map(short_id).unwrap_or("none");
                    let age = status.last_snapshot_at_ms
                        .map(|time| format!("{}ms", now.saturating_sub(time)))
                        .unwrap_or_else(|| "never".into());
                    format!(
                        "repo       {repo_id}\nlease      {lease}\nhead       {head}\nsnapshot   {age} ago\nexposure   {} bytes",
                        status.exposure_bytes
                    )
                }
                Err(error) => format!("authority unavailable\n\n{error:#}"),
            };
            frame.render_widget(
                Paragraph::new(body).block(Block::default().title(" status ").borders(Borders::ALL)),
                areas[1],
            );
            frame.render_widget(
                Paragraph::new("q quit · refreshes every second")
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL)),
                areas[2],
            );
        })?;
        if event::poll(Duration::from_secs(1))?
            && matches!(event::read()?, Event::Key(key) if matches!(key.code, KeyCode::Char('q') | KeyCode::Esc))
        {
            return Ok(());
        }
    }
}
