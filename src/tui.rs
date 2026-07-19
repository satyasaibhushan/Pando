use crate::authority::{Authority, AuthorityStatus, FileAuthority};
use crate::clock::{Clock, SystemClock};
use crate::config::DeviceConfig;
use crate::model::short_id;
use crate::sync::{ForkConflict, ReconcileChoice, Trunk};
use crate::transport::{RemoteAuthority, TransportKey};
use anyhow::{Context, Result, bail};
use crossterm::event::{self, Event, KeyCode};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[derive(Clone, Copy)]
enum PendingAction {
    Authority,
    Local,
    Both,
    Manual,
}

impl PendingAction {
    fn label(self) -> &'static str {
        match self {
            Self::Authority => "keep the network version",
            Self::Local => "keep this device's version",
            Self::Both => "keep both copies",
            Self::Manual => "publish the files currently on disk",
        }
    }
}

pub fn run(config: DeviceConfig) -> Result<()> {
    let mut authority = open_authority(&config)?;
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_loop(&mut terminal, authority.as_mut(), &config);
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    result
}

fn open_authority(config: &DeviceConfig) -> Result<Box<dyn Authority>> {
    if let Some(address) = config.authority.strip_prefix("tcp://") {
        Ok(Box::new(RemoteAuthority::new(
            address,
            TransportKey::load(&config.key_path)?,
        )))
    } else {
        Ok(Box::new(FileAuthority::open(&config.authority)?))
    }
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    authority: &mut dyn Authority,
    config: &DeviceConfig,
) -> Result<()> {
    let clock = SystemClock;
    let mut selected_workspace = 0usize;
    let mut selected_conflict = 0usize;
    let mut pending: Option<PendingAction> = None;
    let mut notice = String::new();

    loop {
        let workspace = &config.workspaces[selected_workspace];
        let status = authority.status(&workspace.id, clock.now_ms());
        let forks = status
            .as_ref()
            .map(|status| status.forks.clone())
            .unwrap_or_default();
        let fork = forks.first();
        let conflicts = fork
            .map(|fork| {
                Trunk::open(
                    config.workspace_path(workspace),
                    &workspace.id,
                    &config.device_id,
                )?
                .fork_conflicts(authority, fork)
            })
            .transpose()
            .unwrap_or_else(|error| {
                notice = format!("Could not inspect conflict: {error:#}");
                None
            })
            .unwrap_or_default();
        selected_conflict = selected_conflict.min(conflicts.len().saturating_sub(1));

        terminal.draw(|frame| {
            let vertical = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(10),
                    Constraint::Length(if pending.is_some() || !notice.is_empty() {
                        5
                    } else {
                        3
                    }),
                ])
                .split(frame.area());
            let horizontal = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(32), Constraint::Percentage(68)])
                .split(vertical[1]);

            frame.render_widget(
                Paragraph::new(format!(
                    " PANDO · {} · {} ",
                    config.device_name,
                    config.root.display()
                ))
                .style(
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )
                .block(Block::default().borders(Borders::ALL)),
                vertical[0],
            );

            let items = config
                .workspaces
                .iter()
                .enumerate()
                .map(|(index, workspace)| {
                    let marker = if index == selected_workspace {
                        "›"
                    } else {
                        " "
                    };
                    ListItem::new(format!("{marker} {}", workspace.name))
                })
                .collect::<Vec<_>>();
            let mut state = ListState::default().with_selected(Some(selected_workspace));
            frame.render_stateful_widget(
                List::new(items)
                    .highlight_style(Style::default().fg(Color::Cyan))
                    .block(Block::default().title(" workspaces ").borders(Borders::ALL)),
                horizontal[0],
                &mut state,
            );

            frame.render_widget(
                Paragraph::new(workspace_body(
                    workspace.name.as_str(),
                    status.as_ref(),
                    &conflicts,
                    selected_conflict,
                ))
                .block(
                    Block::default()
                        .title(" network state ")
                        .borders(Borders::ALL),
                ),
                horizontal[1],
            );

            let footer = if let Some(action) = pending {
                format!(
                    "Confirm {}?  Enter confirm · Esc cancel\n{}",
                    action.label(),
                    notice
                )
            } else if forks.is_empty() {
                format!("↑↓ workspace · q quit · refreshes automatically\n{notice}")
            } else {
                format!(
                    "←→ file · a network · l local · b both · e edit · m manual · q quit\n{notice}"
                )
            };
            frame.render_widget(
                Paragraph::new(footer)
                    .style(Style::default().fg(if pending.is_some() {
                        Color::Yellow
                    } else {
                        Color::DarkGray
                    }))
                    .block(Block::default().borders(Borders::ALL)),
                vertical[2],
            );
        })?;

        if !event::poll(Duration::from_secs(1))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if let Some(action) = pending {
            match key.code {
                KeyCode::Enter => {
                    let Some(fork) = fork else {
                        pending = None;
                        continue;
                    };
                    let trunk = Trunk::open(
                        config.workspace_path(workspace),
                        &workspace.id,
                        &config.device_id,
                    )?;
                    let result = match action {
                        PendingAction::Authority => {
                            trunk.reconcile(authority, &clock, fork, ReconcileChoice::Authority)
                        }
                        PendingAction::Local => {
                            trunk.reconcile(authority, &clock, fork, ReconcileChoice::Fork)
                        }
                        PendingAction::Both => trunk.reconcile_keep_both(authority, &clock, fork),
                        PendingAction::Manual => {
                            trunk.reconcile(authority, &clock, fork, ReconcileChoice::Manual)
                        }
                    };
                    notice = match result {
                        Ok(result) => format!("Resolved at {}", short_id(&result.head)),
                        Err(error) => format!("Resolution failed: {error:#}"),
                    };
                    pending = None;
                }
                KeyCode::Esc => pending = None,
                _ => {}
            }
            continue;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
            KeyCode::Up | KeyCode::Char('k') => {
                selected_workspace = selected_workspace.saturating_sub(1);
                selected_conflict = 0;
                notice.clear();
            }
            KeyCode::Down | KeyCode::Char('j') => {
                selected_workspace =
                    (selected_workspace + 1).min(config.workspaces.len().saturating_sub(1));
                selected_conflict = 0;
                notice.clear();
            }
            KeyCode::Left | KeyCode::Char('h') => {
                selected_conflict = selected_conflict.saturating_sub(1)
            }
            KeyCode::Right => {
                selected_conflict = (selected_conflict + 1).min(conflicts.len().saturating_sub(1))
            }
            KeyCode::Char('a') if !forks.is_empty() => pending = Some(PendingAction::Authority),
            KeyCode::Char('l') if !forks.is_empty() => pending = Some(PendingAction::Local),
            KeyCode::Char('b') if !forks.is_empty() => pending = Some(PendingAction::Both),
            KeyCode::Char('m') if !forks.is_empty() => pending = Some(PendingAction::Manual),
            KeyCode::Char('e') if !conflicts.is_empty() => {
                let conflict = &conflicts[selected_conflict];
                if conflict.path == ".git" || conflict.path.starts_with(".git/") {
                    notice = "Git metadata conflicts cannot be opened in an editor".into();
                } else {
                    notice = edit_file(
                        terminal,
                        &config.workspace_path(workspace).join(&conflict.path),
                    )?;
                }
            }
            _ => {}
        }
    }
}

fn workspace_body(
    name: &str,
    status: Result<&AuthorityStatus, &anyhow::Error>,
    conflicts: &[ForkConflict],
    selected: usize,
) -> String {
    match status {
        Err(error) => format!("{name}\n\nNetwork unavailable\n{error:#}"),
        Ok(status) => {
            let head = status.head.as_deref().map(short_id).unwrap_or("none");
            let lease = status
                .lease
                .as_ref()
                .map(|lease| lease.holder.as_str())
                .unwrap_or("idle");
            if status.forks.is_empty() {
                format!(
                    "{name}\n\n✓ In sync\nhead       {head}\nactivity   {lease}\nexposure   {} bytes",
                    status.exposure_bytes
                )
            } else {
                let paths = conflicts
                    .iter()
                    .enumerate()
                    .take(8)
                    .map(|(index, conflict)| {
                        let marker = if index == selected { "›" } else { " " };
                        let path = if conflict.path.starts_with(".git/") {
                            ".git (repository state)"
                        } else {
                            &conflict.path
                        };
                        format!("{marker} {path}")
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    "{name}\n\n⚠ Needs your decision\n{} pending version(s)\n\nChanged on both sides:\n{paths}",
                    status.forks.len()
                )
            }
        }
    }
}

fn edit_file(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, path: &Path) -> Result<String> {
    let editor = std::env::var("VISUAL")
        .or_else(|_| std::env::var("EDITOR"))
        .unwrap_or_else(|_| "vi".into());
    let mut parts = editor.split_whitespace();
    let program = parts.next().context("EDITOR is empty")?;
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    let status = Command::new(program).args(parts).arg(path).status();
    execute!(terminal.backend_mut(), EnterAlternateScreen)?;
    enable_raw_mode()?;
    terminal.clear()?;
    match status {
        Ok(status) if status.success() => Ok(format!(
            "Edited {}. Press m when the files are resolved.",
            path.display()
        )),
        Ok(status) => Ok(format!("Editor exited with {status}")),
        Err(error) => bail!("start editor {program}: {error}"),
    }
}
