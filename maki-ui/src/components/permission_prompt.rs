use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use maki_agent::permissions::{DEFAULT_DENY_GUIDANCE, PermissionAnswer, generalized_scopes};
use maki_config::ToolKey;

use crate::components::Overlay;
use crate::components::form::{render_form, selected_prefix};
use crate::components::hint_line;
use crate::components::is_ctrl;
use crate::highlight;
use crate::text_buffer::TextBuffer;
use crate::theme;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PermissionOption {
    AllowOnce,
    AllowSession,
    AllowAlwaysLocal,
    AllowAlwaysGlobal,
    Deny,
    DenyWithGuidance,
    DenyAlwaysLocal,
    DenyAlwaysGlobal,
}

struct PermissionMenuItem {
    label: &'static str,
    desc: &'static str,
    option: PermissionOption,
}

const MENU_ITEMS: &[PermissionMenuItem] = &[
    PermissionMenuItem {
        label: "Allow",
        desc: "  Allow this single invocation",
        option: PermissionOption::AllowOnce,
    },
    PermissionMenuItem {
        label: "Allow for session",
        desc: "  Allow for the rest of this session",
        option: PermissionOption::AllowSession,
    },
    PermissionMenuItem {
        label: "Always allow (project)",
        desc: "  Save allow rule to project config",
        option: PermissionOption::AllowAlwaysLocal,
    },
    PermissionMenuItem {
        label: "Always allow (all projects)",
        desc: "  Save allow rule to global config",
        option: PermissionOption::AllowAlwaysGlobal,
    },
    PermissionMenuItem {
        label: "Deny",
        desc: "  Deny this invocation",
        option: PermissionOption::Deny,
    },
    PermissionMenuItem {
        label: "Deny with guidance",
        desc: "  Deny and provide feedback to the model",
        option: PermissionOption::DenyWithGuidance,
    },
    PermissionMenuItem {
        label: "Always deny (project)",
        desc: "  Save deny rule to project config",
        option: PermissionOption::DenyAlwaysLocal,
    },
    PermissionMenuItem {
        label: "Always deny (all projects)",
        desc: "  Save deny rule to global config",
        option: PermissionOption::DenyAlwaysGlobal,
    },
];

const HINT_PAIRS: &[(&str, &str)] = &[
    ("↑↓", "select"),
    ("Enter", "confirm"),
    ("⌃D/⌃U", "scroll"),
    ("Esc", "deny"),
];

const DENY_GUIDANCE_HINTS: &[(&str, &str)] = &[("Enter", "deny"), ("Esc", "cancel")];

fn highlight_bash_spans(text: &str, fallback_style: Style) -> Vec<Span<'static>> {
    let with_nl = if text.ends_with('\n') {
        text.to_string()
    } else {
        format!("{text}\n")
    };
    let mut hl = maki_highlight::Highlighter::for_token("bash");
    let spans = highlight::highlight_line(&mut hl, &with_nl);
    if spans.is_empty() {
        vec![Span::styled(text.to_string(), fallback_style)]
    } else {
        spans
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum PromptState {
    #[default]
    Normal,
    DenyEditing,
}

pub enum PermissionPrompt {
    Closed,
    Open {
        #[allow(dead_code)]
        id: String,
        tool: ToolKey,
        scopes: Vec<String>,
        subagent_id: Option<String>,
        allow_scopes: Vec<String>,
        selected: usize,
        scroll_offset: u16,
        state: PromptState,
        buffer: TextBuffer,
    },
}

impl Overlay for PermissionPrompt {
    fn is_open(&self) -> bool {
        matches!(self, Self::Open { .. })
    }

    fn is_modal(&self) -> bool {
        false
    }

    fn close(&mut self) {
        *self = Self::Closed;
    }
}

impl PermissionPrompt {
    pub fn new() -> Self {
        Self::Closed
    }

    pub fn open(
        &mut self,
        id: String,
        tool: ToolKey,
        scopes: Vec<String>,
        subagent_id: Option<String>,
    ) {
        let mut allow_scopes = generalized_scopes(&tool, &scopes);
        if allow_scopes == scopes {
            allow_scopes = vec![];
        } else {
            let mut seen = std::collections::HashSet::new();
            allow_scopes.retain(|s| seen.insert(s.clone()));
        }
        *self = Self::Open {
            id,
            tool,
            scopes,
            subagent_id,
            allow_scopes,
            selected: 0,
            scroll_offset: 0,
            state: PromptState::Normal,
            buffer: TextBuffer::new(String::new()),
        };
    }

    pub(crate) fn tool(&self) -> Option<&ToolKey> {
        match self {
            Self::Open { tool, .. } => Some(tool),
            Self::Closed => None,
        }
    }

    pub fn subagent_id(&self) -> Option<&str> {
        match self {
            Self::Open { subagent_id, .. } => subagent_id.as_deref(),
            Self::Closed => None,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<PermissionAnswer> {
        let Self::Open {
            state,
            buffer,
            selected,
            scroll_offset,
            ..
        } = self
        else {
            return None;
        };
        if is_ctrl(&key) && key.code == KeyCode::Char('c') {
            return Some(PermissionAnswer::Deny);
        }
        if (is_ctrl(&key) && key.code == KeyCode::Char('d')) || key.code == KeyCode::PageDown {
            *scroll_offset = scroll_offset.saturating_add(4);
            return None;
        }
        if (is_ctrl(&key) && key.code == KeyCode::Char('u')) || key.code == KeyCode::PageUp {
            *scroll_offset = scroll_offset.saturating_sub(4);
            return None;
        }
        if *state == PromptState::DenyEditing {
            return match key.code {
                KeyCode::Enter => {
                    let text = buffer.value().trim().to_string();
                    if text.is_empty() {
                        Some(PermissionAnswer::Deny)
                    } else {
                        Some(PermissionAnswer::DenyWithGuidance(text))
                    }
                }
                KeyCode::Esc => {
                    *buffer = TextBuffer::new(String::new());
                    *state = PromptState::Normal;
                    None
                }
                _ => {
                    buffer.handle_key(key);
                    None
                }
            };
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return None;
        }
        match key.code {
            KeyCode::Up | KeyCode::BackTab => {
                *selected = selected.saturating_sub(1);
                None
            }
            KeyCode::Down | KeyCode::Tab => {
                *selected = (*selected + 1).min(MENU_ITEMS.len() - 1);
                None
            }
            KeyCode::Enter => match MENU_ITEMS[*selected].option {
                PermissionOption::AllowOnce => Some(PermissionAnswer::AllowOnce),
                PermissionOption::AllowSession => Some(PermissionAnswer::AllowSession),
                PermissionOption::AllowAlwaysLocal => Some(PermissionAnswer::AllowAlwaysLocal),
                PermissionOption::AllowAlwaysGlobal => Some(PermissionAnswer::AllowAlwaysGlobal),
                PermissionOption::Deny => Some(PermissionAnswer::Deny),
                PermissionOption::DenyWithGuidance => {
                    *state = PromptState::DenyEditing;
                    None
                }
                PermissionOption::DenyAlwaysLocal => Some(PermissionAnswer::DenyAlwaysLocal),
                PermissionOption::DenyAlwaysGlobal => Some(PermissionAnswer::DenyAlwaysGlobal),
            },
            KeyCode::Esc => Some(PermissionAnswer::Deny),
            _ => None,
        }
    }

    pub fn handle_paste(&mut self, text: &str) -> bool {
        let Self::Open { state, buffer, .. } = self else {
            return false;
        };
        if *state == PromptState::DenyEditing {
            buffer.insert_text(text);
            return true;
        }
        false
    }

    fn build_lines(&self) -> Vec<Line<'static>> {
        let Self::Open {
            tool,
            scopes,
            subagent_id,
            allow_scopes,
            selected,
            state,
            buffer,
            ..
        } = self
        else {
            return vec![];
        };
        let t = theme::current();
        let label_style = t.tool_dim;
        let value_style = Style::new().fg(t.foreground);
        let is_bash = matches!(tool, ToolKey::Native(name) if name.as_ref() == "bash")
            || tool.to_string() == "bash";

        let mut tool_spans = vec![Span::raw("  "), Span::styled("tool  ", label_style)];
        if subagent_id.is_some() {
            tool_spans.push(Span::styled("[subtask] ", t.item_desc));
        }
        tool_spans.push(Span::styled(tool.to_string(), value_style));

        let mut lines = vec![Line::raw(""), Line::from(tool_spans)];
        for (i, s) in scopes.iter().enumerate() {
            let lines_in_scope: Vec<&str> = s.lines().collect();
            if lines_in_scope.is_empty() {
                let label = if i == 0 { "scope " } else { "    + " };
                lines.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(label, label_style),
                ]));
            } else {
                for (line_idx, line_str) in lines_in_scope.iter().enumerate() {
                    let label = if i == 0 && line_idx == 0 {
                        "scope "
                    } else {
                        "    + "
                    };
                    let mut spans = vec![Span::raw("  "), Span::styled(label, label_style)];
                    if is_bash {
                        spans.extend(highlight_bash_spans(line_str, value_style));
                    } else {
                        spans.push(Span::styled((*line_str).to_string(), value_style));
                    }
                    lines.push(Line::from(spans));
                }
            }
        }

        if !allow_scopes.is_empty() {
            for (i, g) in allow_scopes.iter().enumerate() {
                let label = if i == 0 { "allow " } else { "    + " };
                let mut spans = vec![Span::raw("  "), Span::styled(label, label_style)];
                if is_bash {
                    spans.extend(highlight_bash_spans(g, value_style));
                } else {
                    spans.push(Span::styled(g.clone(), value_style));
                }
                lines.push(Line::from(spans));
            }
        }

        lines.push(Line::raw(""));

        match *state {
            PromptState::DenyEditing => {
                let text = buffer.value();
                let (display_text, cursor_pos) = if text.is_empty() {
                    (DEFAULT_DENY_GUIDANCE, 0)
                } else {
                    (text.as_str(), TextBuffer::char_to_byte(&text, buffer.x()))
                };
                let (before, after) = display_text.split_at(cursor_pos);
                let mut chars = after.chars();
                let cursor_ch = chars.next().unwrap_or(' ');
                let rest: String = chars.collect();

                let mut spans = vec![Span::raw("  "), Span::styled("guide ", label_style)];
                if text.is_empty() {
                    spans.push(Span::styled(cursor_ch.to_string(), Style::new().reversed()));
                    spans.push(Span::styled(rest, t.tool_dim));
                } else {
                    spans.push(Span::raw(before.to_string()));
                    spans.push(Span::styled(cursor_ch.to_string(), Style::new().reversed()));
                    if !rest.is_empty() {
                        spans.push(Span::raw(rest));
                    }
                }
                lines.push(Line::from(spans));
                lines.push(Line::raw(""));
                lines.push(hint_line(DENY_GUIDANCE_HINTS));
            }
            PromptState::Normal => {
                for (i, item) in MENU_ITEMS.iter().enumerate() {
                    let (prefix, style) = selected_prefix(&t, i == *selected);
                    let spans = vec![
                        Span::styled(prefix, t.tool_dim),
                        Span::styled(item.label, style),
                        Span::styled(item.desc, t.tool_dim),
                    ];
                    lines.push(Line::from(spans));
                }
                lines.push(Line::raw(""));
                lines.push(hint_line(HINT_PAIRS));
            }
        }
        lines.push(Line::raw(""));
        lines
    }

    pub fn view(&self, frame: &mut Frame, area: Rect) {
        let Self::Open { scroll_offset, .. } = self else {
            return;
        };
        let lines = self.build_lines();
        let t = theme::current();
        let total_lines = lines.len() as u16;
        let visible_height = area.height.saturating_sub(2);
        let max_scroll = total_lines.saturating_sub(visible_height);
        let clamped_scroll = (*scroll_offset).min(max_scroll);
        render_form(
            &t,
            " Permission Required ",
            frame,
            area,
            lines,
            (clamped_scroll, 0),
        );
    }

    pub fn height(&self, width: u16) -> u16 {
        let inner_width = width.saturating_sub(2);
        let lines = self.build_lines();
        let para = Paragraph::new(lines).wrap(Wrap { trim: false });
        para.line_count(inner_width) as u16 + 2
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use maki_agent::permissions::PermissionAnswer;
    use maki_config::ToolKey;

    use super::{MENU_ITEMS, PermissionPrompt, PromptState};

    fn open_prompt() -> PermissionPrompt {
        let mut prompt = PermissionPrompt::new();
        prompt.open(
            "id".into(),
            ToolKey::native("bash"),
            vec!["execute".into()],
            None,
        );
        prompt
    }

    fn ctrl_c() -> KeyEvent {
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn ctrl_c_denies() {
        let mut prompt = open_prompt();
        assert_eq!(prompt.handle_key(ctrl_c()), Some(PermissionAnswer::Deny));
        let mut prompt2 = open_prompt();
        prompt2.handle_key(key(KeyCode::Down));
        prompt2.handle_key(key(KeyCode::Down));
        prompt2.handle_key(key(KeyCode::Down));
        prompt2.handle_key(key(KeyCode::Down));
        prompt2.handle_key(key(KeyCode::Down));
        prompt2.handle_key(key(KeyCode::Enter));
        prompt2.handle_key(key(KeyCode::Char('t')));
        assert_eq!(prompt2.handle_key(ctrl_c()), Some(PermissionAnswer::Deny));
    }

    #[test]
    fn esc_denies_in_normal_mode() {
        let mut prompt = open_prompt();
        assert_eq!(
            prompt.handle_key(key(KeyCode::Esc)),
            Some(PermissionAnswer::Deny)
        );
    }

    #[test]
    fn enter_selects_default_allow() {
        let mut prompt = open_prompt();
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::AllowOnce)
        );
    }

    #[test]
    fn arrow_down_and_up_navigation() {
        let mut prompt = open_prompt();

        prompt.handle_key(key(KeyCode::Up));
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::AllowOnce)
        );

        let mut prompt = open_prompt();
        prompt.handle_key(key(KeyCode::Down));
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::AllowSession)
        );

        let mut prompt = open_prompt();
        prompt.handle_key(key(KeyCode::Down));
        prompt.handle_key(key(KeyCode::Down));
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::AllowAlwaysLocal)
        );

        let mut prompt = open_prompt();
        prompt.handle_key(key(KeyCode::Down));
        prompt.handle_key(key(KeyCode::Down));
        prompt.handle_key(key(KeyCode::Down));
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::AllowAlwaysGlobal)
        );

        let mut prompt = open_prompt();
        prompt.handle_key(key(KeyCode::Down));
        prompt.handle_key(key(KeyCode::Down));
        prompt.handle_key(key(KeyCode::Down));
        prompt.handle_key(key(KeyCode::Down));
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::Deny)
        );

        let mut prompt = open_prompt();
        for _ in 0..6 {
            prompt.handle_key(key(KeyCode::Down));
        }
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::DenyAlwaysLocal)
        );

        let mut prompt = open_prompt();
        for _ in 0..20 {
            prompt.handle_key(key(KeyCode::Down));
        }
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::DenyAlwaysGlobal)
        );

        prompt = open_prompt();
        for _ in 0..7 {
            prompt.handle_key(key(KeyCode::Down));
        }
        prompt.handle_key(key(KeyCode::Up));
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::DenyAlwaysLocal)
        );
    }

    #[test]
    fn deny_with_guidance_flow() {
        let mut prompt = open_prompt();
        for _ in 0..5 {
            prompt.handle_key(key(KeyCode::Down));
        }
        assert_eq!(prompt.handle_key(key(KeyCode::Enter)), None);
        if let PermissionPrompt::Open { state, .. } = &prompt {
            assert_eq!(*state, PromptState::DenyEditing);
        } else {
            panic!("expected Open");
        }

        prompt.handle_key(key(KeyCode::Char('t')));
        assert_eq!(prompt.handle_key(key(KeyCode::Esc)), None);
        if let PermissionPrompt::Open { state, buffer, .. } = &prompt {
            assert_eq!(*state, PromptState::Normal);
            assert!(buffer.value().is_empty());
        } else {
            panic!("expected Open");
        }

        prompt.handle_key(key(KeyCode::Enter));
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::Deny)
        );

        let mut prompt = open_prompt();
        for _ in 0..5 {
            prompt.handle_key(key(KeyCode::Down));
        }
        prompt.handle_key(key(KeyCode::Enter));
        prompt.handle_paste("Use cat");
        assert_eq!(
            prompt.handle_key(key(KeyCode::Enter)),
            Some(PermissionAnswer::DenyWithGuidance("Use cat".into()))
        );
    }

    #[test]
    fn letter_keys_do_not_trigger_decisions() {
        let mut prompt = open_prompt();
        assert_eq!(prompt.handle_key(key(KeyCode::Char('y'))), None);
        assert_eq!(prompt.handle_key(key(KeyCode::Char('n'))), None);
        assert_eq!(prompt.handle_key(key(KeyCode::Char('a'))), None);
        assert_eq!(prompt.handle_key(key(KeyCode::Char('d'))), None);
        assert_eq!(prompt.handle_key(key(KeyCode::Char('s'))), None);
        if let PermissionPrompt::Open { state, .. } = &prompt {
            assert_eq!(*state, PromptState::Normal);
        }
    }

    #[test]
    fn handle_paste_requires_editing_mode() {
        let mut prompt = open_prompt();
        assert!(!prompt.handle_paste("ignored"));
        for _ in 0..5 {
            prompt.handle_key(key(KeyCode::Down));
        }
        prompt.handle_key(key(KeyCode::Enter));
        assert!(prompt.handle_paste("accepted"));
        if let PermissionPrompt::Open { buffer, .. } = &prompt {
            assert_eq!(buffer.value(), "accepted");
        } else {
            panic!("expected Open");
        }
    }

    #[test]
    fn ctrl_d_and_ctrl_u_scroll() {
        let mut prompt = open_prompt();
        let ctrl_d = KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL);
        let ctrl_u = KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL);

        assert_eq!(prompt.handle_key(ctrl_d), None);
        if let PermissionPrompt::Open { scroll_offset, .. } = &prompt {
            assert_eq!(*scroll_offset, 4);
        }

        assert_eq!(prompt.handle_key(key(KeyCode::PageDown)), None);
        if let PermissionPrompt::Open { scroll_offset, .. } = &prompt {
            assert_eq!(*scroll_offset, 8);
        }

        assert_eq!(prompt.handle_key(ctrl_u), None);
        if let PermissionPrompt::Open { scroll_offset, .. } = &prompt {
            assert_eq!(*scroll_offset, 4);
        }

        assert_eq!(prompt.handle_key(key(KeyCode::PageUp)), None);
        if let PermissionPrompt::Open { scroll_offset, .. } = &prompt {
            assert_eq!(*scroll_offset, 0);
        }
    }

    #[test]
    fn multiline_bash_scope_splits_lines() {
        let mut prompt = PermissionPrompt::new();
        prompt.open(
            "id".into(),
            ToolKey::native("bash"),
            vec!["echo hello\necho world".into()],
            None,
        );
        let lines = prompt.build_lines();
        let rendered: Vec<String> = lines
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<Vec<_>>()
                    .join("")
            })
            .collect();
        assert!(rendered.iter().any(|l| l.contains("echo hello")));
        assert!(rendered.iter().any(|l| l.contains("echo world")));
    }

    #[test]
    fn bash_scope_syntax_highlighted() {
        let mut prompt = PermissionPrompt::new();
        prompt.open(
            "id".into(),
            ToolKey::native("bash"),
            vec!["git commit -m \"fix bug\"".into()],
            None,
        );
        let lines = prompt.build_lines();
        let scope_line = lines
            .iter()
            .find(|l| {
                let text: String = l.spans.iter().map(|s| s.content.as_ref()).collect();
                text.contains("git commit")
            })
            .expect("should have scope line");
        assert!(
            scope_line.spans.len() > 2,
            "should have highlighted tokens for git command"
        );
    }

    #[test]
    fn allow_scopes_are_deduplicated() {
        let mut prompt = PermissionPrompt::new();
        prompt.open(
            "id".into(),
            ToolKey::native("bash"),
            vec![
                "git add .".into(),
                "git commit -m \"msg\"".into(),
                "git push origin main".into(),
            ],
            None,
        );
        if let PermissionPrompt::Open { allow_scopes, .. } = &prompt {
            assert_eq!(allow_scopes, &vec!["git *".to_string()]);
        } else {
            panic!("expected Open");
        }
    }

    #[test]
    fn wildcard_tool_key_opens() {
        let mut prompt = PermissionPrompt::new();
        prompt.open("id".into(), ToolKey::Wildcard, vec![], None);
        assert!(matches!(prompt, PermissionPrompt::Open { .. }));
    }

    #[test]
    fn menu_items_count() {
        assert_eq!(MENU_ITEMS.len(), 8);
    }
}
