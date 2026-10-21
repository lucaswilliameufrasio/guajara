use super::*;
use guajara::remote::{self, Client, Snapshot};
use ratatui::widgets::{ListState, Wrap};

pub(super) enum Launch {
    Manage(String),
    Copy(Vec<usize>),
}

struct Session {
    client: Client,
    original: Snapshot,
    config: SshConfig,
}

#[derive(Clone)]
struct HostForm {
    index: Option<usize>,
    fields: Vec<(String, String)>,
    focus: usize,
    editing: Option<String>,
}

#[derive(Clone)]
enum IdentityPurpose {
    Form(HostForm),
    Copy {
        indices: Vec<usize>,
        assignments: Vec<(usize, Option<String>)>,
    },
}

enum View {
    Destinations {
        aliases: Vec<String>,
        selected: usize,
        indices: Vec<usize>,
    },
    Hosts {
        selected: usize,
    },
    Detail(usize),
    Form(HostForm),
    Keys {
        paths: Vec<PathBuf>,
        selected: usize,
        purpose: IdentityPurpose,
    },
    KeyName {
        value: String,
        purpose: IdentityPurpose,
    },
    IdentityPath {
        value: String,
        purpose: IdentityPurpose,
    },
    Preview {
        updated: SshConfig,
        previous: Box<View>,
        scroll: u16,
    },
    Message {
        text: String,
        previous: Box<View>,
    },
}

enum Effect {
    None,
    Open {
        destination: String,
        indices: Vec<usize>,
    },
    Keys(IdentityPurpose),
    CreateKey {
        name: String,
        purpose: IdentityPurpose,
    },
    Save(SshConfig),
    Test(String),
    Reload,
    Exit,
}

struct RemoteApp {
    source: SshConfig,
    local_path: PathBuf,
    session: Option<Session>,
    view: View,
}

impl HostForm {
    fn new(config: &SshConfig, index: Option<usize>) -> Self {
        let hosts = config.hosts();
        let host = index.and_then(|index| hosts.get(index));
        let patterns = host.map(|host| host.patterns.join(" ")).unwrap_or_default();
        let mut fields = vec![("Patterns".into(), patterns)];
        for key in ["HostName", "User", "Port", "IdentityFile"] {
            let value = host
                .and_then(|host| {
                    host.directives
                        .iter()
                        .find(|directive| directive.key.eq_ignore_ascii_case(key))
                })
                .map(|directive| directive.value.clone())
                .unwrap_or_default();
            fields.push((key.into(), value));
        }
        fields.extend([
            ("Save".into(), String::new()),
            ("Cancel".into(), String::new()),
        ]);
        Self {
            index,
            fields,
            focus: 0,
            editing: None,
        }
    }

    fn apply(&self, config: &SshConfig) -> Result<SshConfig, String> {
        let patterns: Vec<String> = self.fields[0]
            .1
            .split_whitespace()
            .map(String::from)
            .collect();
        if patterns.is_empty()
            || self
                .fields
                .iter()
                .any(|(_, value)| value.chars().any(char::is_control))
        {
            return Err(
                "Host patterns are required and fields must not contain control characters".into(),
            );
        }
        if !self.fields[3].1.is_empty()
            && !self.fields[3].1.parse::<u16>().is_ok_and(|port| port > 0)
        {
            return Err("Port must be between 1 and 65535".into());
        }
        let hosts = config.hosts();
        for (index, host) in hosts.iter().enumerate() {
            if Some(index) != self.index
                && patterns
                    .iter()
                    .any(|pattern| host.patterns.contains(pattern))
            {
                return Err("A host with one of these aliases already exists".into());
            }
        }
        let mut updated = config.clone();
        if let Some(index) = self.index {
            let host = hosts
                .get(index)
                .ok_or("Remote host no longer exists; reload")?;
            let indent: String = updated.lines[host.header_idx]
                .chars()
                .take_while(|character| character.is_whitespace())
                .collect();
            updated.lines[host.header_idx] = format!("{indent}Host {}", patterns.join(" "));
            for (key, value) in &self.fields[1..5] {
                if value.is_empty() {
                    let _ = updated.unset(host.start_idx, key);
                } else {
                    if key == "IdentityFile" {
                        let _ = updated.unset(host.start_idx, key);
                    }
                    updated.set(host.start_idx, key, value)?;
                }
            }
        } else {
            let directives: Vec<(String, String)> = self.fields[1..5]
                .iter()
                .filter(|(_, value)| !value.is_empty())
                .cloned()
                .collect();
            updated.add(&patterns, &directives);
        }
        Ok(updated)
    }
}

impl RemoteApp {
    fn message(&mut self, text: String) {
        let previous = std::mem::replace(&mut self.view, View::Hosts { selected: 0 });
        self.view = View::Message {
            text,
            previous: Box::new(previous),
        };
    }

    fn preview(&mut self, updated: SshConfig) {
        let previous = std::mem::replace(&mut self.view, View::Hosts { selected: 0 });
        self.view = View::Preview {
            updated,
            previous: Box::new(previous),
            scroll: 0,
        };
    }

    fn choose_identity(
        &mut self,
        purpose: IdentityPurpose,
        identity: Option<String>,
    ) -> Result<Effect, String> {
        match purpose {
            IdentityPurpose::Form(mut form) => {
                form.fields[4].1 = identity
                    .map(|path| remote::config_path(&path))
                    .unwrap_or_default();
                self.view = View::Form(form);
                Ok(Effect::None)
            }
            IdentityPurpose::Copy {
                indices,
                mut assignments,
            } => {
                let index = *indices
                    .get(assignments.len())
                    .ok_or("Invalid copy selection")?;
                assignments.push((index, identity));
                if assignments.len() == indices.len() {
                    let session = self.session.as_ref().ok_or("No remote session")?;
                    let updated = remote::copy_hosts(&self.source, &assignments, &session.config)?;
                    self.view = View::Hosts { selected: 0 };
                    self.preview(updated);
                    Ok(Effect::None)
                } else {
                    Ok(Effect::Keys(IdentityPurpose::Copy {
                        indices,
                        assignments,
                    }))
                }
            }
        }
    }

    fn handle(&mut self, key: event::KeyEvent) -> Result<Effect, String> {
        match &mut self.view {
            View::Message { .. } => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
                    let view = std::mem::replace(&mut self.view, View::Hosts { selected: 0 });
                    if let View::Message { previous, .. } = view {
                        self.view = *previous;
                    }
                }
            }
            View::Destinations {
                aliases,
                selected,
                indices,
            } => match key.code {
                KeyCode::Esc => return Ok(Effect::Exit),
                KeyCode::Down | KeyCode::Char('j') if !aliases.is_empty() => {
                    *selected = (*selected + 1) % aliases.len()
                }
                KeyCode::Up | KeyCode::Char('k') if !aliases.is_empty() => {
                    *selected = (*selected + aliases.len() - 1) % aliases.len()
                }
                KeyCode::Enter => {
                    if let Some(destination) = aliases.get(*selected) {
                        return Ok(Effect::Open {
                            destination: destination.clone(),
                            indices: indices.clone(),
                        });
                    }
                }
                _ => {}
            },
            View::Hosts { selected } => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('q')) {
                    return Ok(Effect::Exit);
                }
                let session = self.session.as_ref().ok_or("No remote session")?;
                let hosts = session.config.hosts();
                match key.code {
                    KeyCode::Esc | KeyCode::Char('q') => return Ok(Effect::Exit),
                    KeyCode::Char('r') => return Ok(Effect::Reload),
                    KeyCode::Down | KeyCode::Char('j') if !hosts.is_empty() => {
                        *selected = (*selected + 1) % hosts.len()
                    }
                    KeyCode::Up | KeyCode::Char('k') if !hosts.is_empty() => {
                        *selected = (*selected + hosts.len() - 1) % hosts.len()
                    }
                    KeyCode::Enter if *selected < hosts.len() => {
                        self.view = View::Detail(*selected)
                    }
                    KeyCode::Char('a') => {
                        self.view = View::Form(HostForm::new(&session.config, None))
                    }
                    KeyCode::Char('e') if *selected < hosts.len() => {
                        self.view = View::Form(HostForm::new(&session.config, Some(*selected)))
                    }
                    KeyCode::Char('d') if *selected < hosts.len() => {
                        let mut updated = session.config.clone();
                        updated.remove_block(hosts[*selected].start_idx)?;
                        self.preview(updated);
                    }
                    KeyCode::Char('t') if *selected < hosts.len() => {
                        let alias = hosts[*selected]
                            .patterns
                            .iter()
                            .find(|alias| guajara::connection::is_concrete_host(alias))
                            .ok_or("This block has no concrete alias to test")?;
                        return Ok(Effect::Test(alias.clone()));
                    }
                    _ => {}
                }
            }
            View::Detail(index) => {
                let session = self.session.as_ref().ok_or("No remote session")?;
                match key.code {
                    KeyCode::Esc => self.view = View::Hosts { selected: *index },
                    KeyCode::Char('e') => {
                        self.view = View::Form(HostForm::new(&session.config, Some(*index)))
                    }
                    KeyCode::Char('t') => {
                        let hosts = session.config.hosts();
                        let alias = hosts
                            .get(*index)
                            .and_then(|host| {
                                host.patterns
                                    .iter()
                                    .find(|alias| guajara::connection::is_concrete_host(alias))
                            })
                            .ok_or("This block has no concrete alias to test")?;
                        return Ok(Effect::Test(alias.clone()));
                    }
                    _ => {}
                }
            }
            View::Form(form) => {
                if let Some(buffer) = &mut form.editing {
                    match key.code {
                        KeyCode::Enter => {
                            form.fields[form.focus].1 = form.editing.take().unwrap_or_default()
                        }
                        KeyCode::Esc => form.editing = None,
                        KeyCode::Backspace => {
                            buffer.pop();
                        }
                        KeyCode::Char(character) if !character.is_control() => {
                            buffer.push(character)
                        }
                        _ => {}
                    }
                } else {
                    match key.code {
                        KeyCode::Esc => {
                            self.view = View::Hosts {
                                selected: form.index.unwrap_or(0),
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            form.focus = (form.focus + 1) % form.fields.len()
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            form.focus = (form.focus + form.fields.len() - 1) % form.fields.len()
                        }
                        KeyCode::Enter => match form.focus {
                            4 => return Ok(Effect::Keys(IdentityPurpose::Form(form.clone()))),
                            5 => {
                                let updated = form.apply(
                                    &self.session.as_ref().ok_or("No remote session")?.config,
                                )?;
                                self.preview(updated);
                            }
                            6 => {
                                self.view = View::Hosts {
                                    selected: form.index.unwrap_or(0),
                                }
                            }
                            _ => form.editing = Some(form.fields[form.focus].1.clone()),
                        },
                        _ => {}
                    }
                }
            }
            View::Keys {
                paths,
                selected,
                purpose,
            } => {
                let count = paths.len() + 3;
                match key.code {
                    KeyCode::Esc => {
                        self.view = match purpose.clone() {
                            IdentityPurpose::Form(form) => View::Form(form),
                            IdentityPurpose::Copy { .. } => View::Hosts { selected: 0 },
                        };
                    }
                    KeyCode::Down | KeyCode::Char('j') => *selected = (*selected + 1) % count,
                    KeyCode::Up | KeyCode::Char('k') => *selected = (*selected + count - 1) % count,
                    KeyCode::Enter => {
                        let purpose = purpose.clone();
                        if let Some(path) = paths.get(*selected) {
                            let path = path.to_str().ok_or("Invalid remote key path")?.to_string();
                            return self.choose_identity(purpose, Some(path));
                        }
                        match *selected - paths.len() {
                            0 => {
                                self.view = View::KeyName {
                                    value: String::new(),
                                    purpose,
                                }
                            }
                            1 => {
                                self.view = View::IdentityPath {
                                    value: String::new(),
                                    purpose,
                                }
                            }
                            _ => return self.choose_identity(purpose, None),
                        }
                    }
                    _ => {}
                }
            }
            View::KeyName { value, purpose } | View::IdentityPath { value, purpose } => {
                match key.code {
                    KeyCode::Esc => return Ok(Effect::Keys(purpose.clone())),
                    KeyCode::Backspace => {
                        value.pop();
                    }
                    KeyCode::Char(character) if !character.is_control() => value.push(character),
                    KeyCode::Enter => {
                        let value = value.clone();
                        let purpose = purpose.clone();
                        if matches!(self.view, View::KeyName { .. }) {
                            remote::validate_key_name(&value)?;
                            return Ok(Effect::CreateKey {
                                name: value,
                                purpose,
                            });
                        }
                        if !(value.starts_with('/') || value.starts_with("~/")) {
                            return Err(
                                "Use an absolute path or ~/ path on the remote machine".into()
                            );
                        }
                        return self.choose_identity(purpose, Some(value));
                    }
                    _ => {}
                }
            }
            View::Preview {
                updated, scroll, ..
            } => match key.code {
                KeyCode::Esc | KeyCode::Char('n') => {
                    let view = std::mem::replace(&mut self.view, View::Hosts { selected: 0 });
                    if let View::Preview { previous, .. } = view {
                        self.view = *previous;
                    }
                }
                KeyCode::Char('y') => return Ok(Effect::Save(updated.clone())),
                KeyCode::Down | KeyCode::Char('j') => *scroll = scroll.saturating_add(1),
                KeyCode::Up | KeyCode::Char('k') => *scroll = scroll.saturating_sub(1),
                _ => {}
            },
        }
        Ok(Effect::None)
    }

    fn apply(&mut self, effect: Effect) -> Result<(), String> {
        match effect {
            Effect::Open {
                destination,
                indices,
            } => {
                let client = Client::new(&self.local_path, &destination)?;
                let original = client.read()?;
                let config = SshConfig::parse(&original.content);
                if !indices.is_empty() {
                    remote::check_copy(&self.source, &indices, &config)?;
                }
                self.session = Some(Session {
                    client,
                    original,
                    config,
                });
                self.view = View::Hosts { selected: 0 };
                if !indices.is_empty() {
                    self.apply(Effect::Keys(IdentityPurpose::Copy {
                        indices,
                        assignments: Vec::new(),
                    }))?;
                }
            }
            Effect::Keys(purpose) => {
                let paths = self
                    .session
                    .as_ref()
                    .ok_or("No remote session")?
                    .client
                    .keys()?;
                self.view = View::Keys {
                    paths,
                    selected: 0,
                    purpose,
                };
            }
            Effect::CreateKey { name, purpose } => {
                let path = self
                    .session
                    .as_ref()
                    .ok_or("No remote session")?
                    .client
                    .create_key(&name)?;
                let next =
                    self.choose_identity(purpose, Some(path.to_string_lossy().into_owned()))?;
                self.apply(next)?;
                println!(
                    "Remote key created. It remains on the remote machine even if you cancel the form or copy."
                );
            }
            Effect::Save(updated) => {
                let session = self.session.as_mut().ok_or("No remote session")?;
                let content = updated.to_string();
                session.client.write(&session.original, &content)?;
                session.original = Snapshot {
                    exists: true,
                    content,
                };
                session.config = updated;
                self.view = View::Hosts { selected: 0 };
                self.message("Remote SSH config saved.".into());
            }
            Effect::Test(alias) => {
                self.session
                    .as_ref()
                    .ok_or("No remote session")?
                    .client
                    .test_host(&alias)?;
                self.message(format!(
                    "Successfully connected to '{alias}' from the remote machine."
                ));
            }
            Effect::Reload => {
                let session = self.session.as_mut().ok_or("No remote session")?;
                let original = session.client.read()?;
                session.config = SshConfig::parse(&original.content);
                session.original = original;
                self.view = View::Hosts { selected: 0 };
            }
            Effect::None | Effect::Exit => {}
        }
        Ok(())
    }

    fn render(&self, frame: &mut Frame) {
        let layout = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(frame.area());
        let destination = self
            .session
            .as_ref()
            .map(|session| session.client.destination.as_str())
            .unwrap_or("select destination");
        frame.render_widget(Paragraph::new(format!(" Guajará — REMOTE: {destination}\n Remote ~/.ssh/config — local files and private keys are not transferred")), layout[0]);
        self.render_view(frame, layout[1], &self.view);
        let help = match &self.view {
            View::Hosts { .. } => {
                "j/k navigate  Enter details  a add  e edit  d delete  t test FROM remote  r reload  Esc local"
            }
            View::Detail(_) => "e edit  t test FROM remote  Esc list",
            View::Preview { .. } => {
                "j/k scroll  y CONFIRM remote write  n/Esc cancel — review paths, Include and ProxyJump dependencies"
            }
            View::Form(form) if form.editing.is_some() => {
                "Type value  Enter apply field  Esc cancel field"
            }
            View::Form(_) => "j/k field  Enter edit/select/save  Esc cancel",
            View::Message { .. } => "Enter/Esc close",
            View::KeyName { .. } => {
                "Filename only  Enter create ON REMOTE  Esc back — created keys are not removed on cancel"
            }
            View::IdentityPath { .. } => "Remote absolute or ~/ path  Enter select  Esc back",
            _ => "j/k navigate  Enter select  Esc cancel",
        };
        frame.render_widget(Paragraph::new(help).wrap(Wrap { trim: false }), layout[2]);
    }

    fn render_view(&self, frame: &mut Frame, area: Rect, view: &View) {
        match view {
            View::Destinations {
                aliases, selected, ..
            } => render_options(
                frame,
                area,
                " Copy selected hosts to… ",
                aliases.clone(),
                *selected,
            ),
            View::Hosts { selected } => {
                let options = self
                    .session
                    .as_ref()
                    .map(|session| {
                        session
                            .config
                            .hosts()
                            .iter()
                            .map(|host| host.patterns.join(" "))
                            .collect()
                    })
                    .unwrap_or_default();
                render_options(
                    frame,
                    area,
                    " Remote SSH hosts (a add) ",
                    options,
                    *selected,
                );
            }
            View::Detail(index) => {
                if let Some(session) = &self.session
                    && let Some(host) = session.config.hosts().get(*index)
                {
                    let text = session.config.lines[host.start_idx..host.end_idx].join("\n");
                    frame.render_widget(
                        Paragraph::new(text)
                            .block(Block::bordered().title(" Remote SSH host "))
                            .wrap(Wrap { trim: false }),
                        area,
                    );
                }
            }
            View::Form(form) => {
                let options = form
                    .fields
                    .iter()
                    .enumerate()
                    .map(|(index, (key, value))| {
                        let value = if index == form.focus {
                            form.editing.as_deref().unwrap_or(value)
                        } else {
                            value
                        };
                        format!("{key:<14} {value}")
                    })
                    .collect();
                render_options(
                    frame,
                    area,
                    " Remote host — IdentityFile selects REMOTE keys ",
                    options,
                    form.focus,
                );
            }
            View::Keys {
                paths,
                selected,
                purpose,
            } => {
                let title = match purpose {
                    IdentityPurpose::Form(_) => " Remote IdentityFile ".into(),
                    IdentityPurpose::Copy {
                        indices,
                        assignments,
                    } => {
                        let hosts = self.source.hosts();
                        let name = indices
                            .get(assignments.len())
                            .and_then(|index| hosts.get(*index))
                            .map(|host| host.patterns.join(" "))
                            .unwrap_or_default();
                        format!(
                            " Remote key for {name} ({}/{}) ",
                            assignments.len() + 1,
                            indices.len()
                        )
                    }
                };
                let mut options: Vec<String> = paths
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect();
                options.extend([
                    "Create new key ON REMOTE…".into(),
                    "Enter REMOTE path manually…".into(),
                    "Use remote SSH default identities (no IdentityFile)".into(),
                ]);
                render_options(frame, area, &title, options, *selected);
            }
            View::KeyName { value, .. } | View::IdentityPath { value, .. } => {
                frame.render_widget(
                    Paragraph::new(format!("{value}▏"))
                        .block(Block::bordered().title(" Remote identity — never a local key ")),
                    area,
                );
            }
            View::Preview {
                updated, scroll, ..
            } => {
                let original = self
                    .session
                    .as_ref()
                    .map(|session| session.original.content.as_str())
                    .unwrap_or_default();
                frame.render_widget(
                    Paragraph::new(diff(original, &updated.to_string()))
                        .scroll((*scroll, 0))
                        .block(
                            Block::bordered()
                                .title(" Preview REMOTE write — y confirm / n cancel "),
                        ),
                    area,
                );
            }
            View::Message { text, .. } => {
                frame.render_widget(
                    Paragraph::new(text.as_str())
                        .wrap(Wrap { trim: false })
                        .block(Block::bordered().title(" Remote SSH ")),
                    area,
                );
            }
        }
    }
}

fn render_options(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    options: Vec<String>,
    selected: usize,
) {
    let mut state = ListState::default().with_selected(Some(selected));
    frame.render_stateful_widget(
        List::new(options)
            .block(Block::bordered().title(title))
            .highlight_symbol("> ")
            .highlight_style(Style::default().fg(Color::Black).bg(Color::Cyan)),
        area,
        &mut state,
    );
}

pub(super) fn run(
    terminal: &mut Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    local_path: &Path,
    source: &SshConfig,
    launch: Launch,
) {
    let aliases: Vec<String> = SshConfig::parse(&read_file(local_path).unwrap_or_default())
        .hosts()
        .into_iter()
        .flat_map(|host| host.patterns)
        .filter(|alias| guajara::connection::is_concrete_host(alias))
        .collect();
    let (view, initial) = match launch {
        Launch::Manage(destination) if aliases.contains(&destination) => (
            View::Hosts { selected: 0 },
            Effect::Open {
                destination,
                indices: Vec::new(),
            },
        ),
        Launch::Manage(_) => (
            View::Message {
                text: "Save the destination host in the local SSH config before connecting.".into(),
                previous: Box::new(View::Hosts { selected: 0 }),
            },
            Effect::None,
        ),
        Launch::Copy(indices) => (
            View::Destinations {
                aliases,
                selected: 0,
                indices,
            },
            Effect::None,
        ),
    };
    let mut app = RemoteApp {
        source: source.clone(),
        local_path: local_path.to_path_buf(),
        session: None,
        view,
    };
    let mut effect = initial;
    loop {
        if !matches!(effect, Effect::None) {
            if matches!(effect, Effect::Exit) {
                break;
            }
            let wait = matches!(effect, Effect::CreateKey { .. } | Effect::Test(_));
            let result = (|| {
                disable_raw_mode().map_err(|error| error.to_string())?;
                stdout()
                    .execute(LeaveAlternateScreen)
                    .map_err(|error| error.to_string())?;
                println!("Guajará: remote SSH operation. Authentication is handled by OpenSSH.");
                let result = app.apply(effect);
                if let Err(error) = &result {
                    eprintln!("{error}");
                }
                if wait || result.is_err() {
                    println!("Press Enter to return to Guajará.");
                    stdout().flush().ok();
                    let mut input = String::new();
                    std::io::stdin()
                        .read_line(&mut input)
                        .map_err(|error| error.to_string())?;
                }
                result
            })();
            stdout().execute(EnterAlternateScreen).ok();
            enable_raw_mode().ok();
            terminal.clear().ok();
            if let Err(error) = result {
                app.message(error);
            }
        }
        terminal.draw(|frame| app.render(frame)).ok();
        effect = Effect::None;
        if event::poll(Duration::from_millis(200)).unwrap_or(false)
            && let Ok(Event::Key(key)) = event::read()
            && key.kind == KeyEventKind::Press
        {
            match app.handle(key) {
                Ok(next) => effect = next,
                Err(error) => app.message(error),
            }
        }
    }
    terminal.clear().ok();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> RemoteApp {
        let original = Snapshot {
            exists: true,
            content: "# preserve\nHost remote-existing\n    User alice\n".into(),
        };
        RemoteApp {
            source: SshConfig::parse(
                "Host first\n IdentityFile /local/private\nHost second\n IdentityFile /local/other\n",
            ),
            local_path: PathBuf::from("/nonexistent/local-config"),
            session: Some(Session {
                client: Client::new(Path::new("/nonexistent/local-config"), "destination").unwrap(),
                config: SshConfig::parse(&original.content),
                original,
            }),
            view: View::Hosts { selected: 0 },
        }
    }

    #[test]
    fn should_edit_remote_host_only_after_diff_confirmation() {
        let mut app = app();
        app.handle(KeyCode::Char('e').into()).unwrap();
        let View::Form(form) = &mut app.view else {
            panic!("Expected remote form");
        };
        form.fields[2].1 = "bob".into();
        form.focus = 5;
        assert!(matches!(
            app.handle(KeyCode::Enter.into()).unwrap(),
            Effect::None
        ));
        let View::Preview { updated, .. } = &app.view else {
            panic!("Expected diff preview");
        };
        assert!(updated.to_string().contains("User bob"));
        assert!(updated.to_string().contains("# preserve"));
        assert!(
            app.session
                .as_ref()
                .unwrap()
                .config
                .to_string()
                .contains("User alice")
        );
        assert!(matches!(
            app.handle(KeyCode::Char('y').into()).unwrap(),
            Effect::Save(_)
        ));
        app.handle(KeyCode::Esc.into()).unwrap();
        assert!(matches!(app.view, View::Form(_)));
        assert_eq!(
            app.session.as_ref().unwrap().original.content,
            "# preserve\nHost remote-existing\n    User alice\n"
        );
    }

    #[test]
    fn should_assign_separate_remote_identities_to_a_batch_before_one_preview() {
        let mut app = app();
        let purpose = IdentityPurpose::Copy {
            indices: vec![0, 1],
            assignments: Vec::new(),
        };
        let Effect::Keys(purpose) = app
            .choose_identity(purpose, Some("/remote/first-key".into()))
            .unwrap()
        else {
            panic!("Expected next host identity");
        };
        app.choose_identity(purpose, Some("~/.ssh/second-key".into()))
            .unwrap();
        let View::Preview { updated, .. } = &app.view else {
            panic!("Expected batch preview");
        };
        let content = updated.to_string();
        assert!(content.contains("/remote/first-key"));
        assert!(content.contains("~/.ssh/second-key"));
        assert!(!content.contains("/local/"));
        assert_eq!(updated.hosts().len(), 3);
        assert_eq!(app.session.as_ref().unwrap().config.hosts().len(), 1);
    }

    #[test]
    fn should_preview_deletion_and_cancel_without_mutating_remote_snapshot() {
        let mut app = app();
        app.handle(KeyCode::Char('d').into()).unwrap();
        let View::Preview { updated, .. } = &app.view else {
            panic!("Expected deletion preview");
        };
        assert!(updated.hosts().is_empty());
        assert_eq!(app.session.as_ref().unwrap().config.hosts().len(), 1);
        app.handle(KeyCode::Esc.into()).unwrap();
        assert!(matches!(app.view, View::Hosts { .. }));
        assert_eq!(app.session.as_ref().unwrap().config.hosts().len(), 1);
    }

    #[test]
    fn should_select_remote_key_and_allow_manual_path_or_creation_without_local_discovery() {
        let mut app = app();
        let form = HostForm::new(&app.session.as_ref().unwrap().config, Some(0));
        app.view = View::Keys {
            paths: vec![PathBuf::from("/destination/key")],
            selected: 0,
            purpose: IdentityPurpose::Form(form.clone()),
        };
        app.handle(KeyCode::Enter.into()).unwrap();
        let View::Form(updated) = &app.view else {
            panic!("Expected form");
        };
        assert_eq!(updated.fields[4].1, "\"/destination/key\"");
        app.view = View::Keys {
            paths: Vec::new(),
            selected: 0,
            purpose: IdentityPurpose::Form(form.clone()),
        };
        app.handle(KeyCode::Enter.into()).unwrap();
        assert!(matches!(app.view, View::KeyName { .. }));
        for character in "id_remote".chars() {
            app.handle(KeyCode::Char(character).into()).unwrap();
        }
        assert!(
            matches!(app.handle(KeyCode::Enter.into()).unwrap(), Effect::CreateKey { name, .. } if name == "id_remote")
        );
        app.view = View::IdentityPath {
            value: "local-relative".into(),
            purpose: IdentityPurpose::Form(form),
        };
        assert!(app.handle(KeyCode::Enter.into()).is_err());
    }

    #[test]
    fn should_leave_after_connection_failure_without_requiring_a_remote_session() {
        let mut app = app();
        app.session = None;
        app.message("Connection failed".into());
        app.handle(KeyCode::Enter.into()).unwrap();
        assert!(matches!(
            app.handle(KeyCode::Esc.into()).unwrap(),
            Effect::Exit
        ));
    }

    #[test]
    fn should_reject_duplicate_remote_aliases_and_invalid_ports() {
        let config = SshConfig::parse("Host first\n    CustomOption keep\nHost second\n");
        let mut form = HostForm::new(&config, Some(0));
        form.fields[0].1 = "second".into();
        assert!(form.apply(&config).is_err());
        form.fields[0].1 = "first".into();
        form.fields[3].1 = "70000".into();
        assert!(form.apply(&config).is_err());
        form.fields[3].1 = "22".into();
        assert!(
            form.apply(&config)
                .unwrap()
                .to_string()
                .contains("CustomOption keep")
        );
    }

    #[test]
    fn should_render_remote_destination_and_batch_identity_progress() {
        let mut app = app();
        app.view = View::Keys {
            paths: Vec::new(),
            selected: 0,
            purpose: IdentityPurpose::Copy {
                indices: vec![0, 1],
                assignments: Vec::new(),
            },
        };
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| app.render(frame)).unwrap();
        let text: String = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("REMOTE: destination"));
        assert!(text.contains("Remote key for first (1/2)"));
        assert!(text.contains("Create new key ON REMOTE"));
    }
}
