//! Where the text for a person goes, and what changes with it: whether standard output is a
//! terminal, whether it takes colour, and how wide it is. Made once per command and handed to
//! the text renderers (`text.rs`), so that a test renders with a screen of its own and never
//! with the terminal it runs in.
//!
//! What is adopted, from the common practice of mature command-line tools (clig.dev, the GitHub
//! CLI and its Primer guidelines, cargo, `NO_COLOR`): colour only on a terminal, never when
//! `NO_COLOR` is set or `TERM` is `dumb`, and never the only carrier of meaning; only the eight
//! basic colours, bold and dim, so the terminal's own palette decides the shade; columns cut to
//! the terminal's width and whole in a pipe; relative times on a terminal and exact ones in a
//! pipe. Nothing here is Immunity Core's own design.
//!
//! The one rule a review tries to break: every text this module measures, cuts or styles is
//! already escaped (`view::shown`, on what `known::whole` made), and a style sequence is written
//! only here, around such text. `paint` escapes what it is given once more, which changes
//! nothing in escaped text, so text from a source can never open or close a style.

use crate::view;
use std::io::IsTerminal;

/// Where the text goes: see the module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Screen {
    /// Standard output is a terminal.
    pub terminal: bool,
    /// A terminal, `NO_COLOR` unset or empty, and `TERM` not `dumb`.
    pub colour: bool,
    /// The terminal's columns; none in a pipe, where nothing is cut.
    pub width: Option<usize>,
}

/// The width taken when a terminal does not say its own.
const FALLBACK_WIDTH: usize = 80;

impl Screen {
    /// The screen of this process's standard output and environment.
    pub fn of_stdout() -> Screen {
        let terminal = std::io::stdout().is_terminal();
        Screen::decide(
            terminal,
            std::env::var_os("NO_COLOR"),
            std::env::var_os("TERM"),
            if terminal {
                asked_width(libc::STDOUT_FILENO)
            } else {
                None
            },
        )
    }

    /// The screen of this process's standard error, where a refusal or a failure is told to a
    /// person: the same rules, asked of standard error.
    pub fn of_stderr() -> Screen {
        let terminal = std::io::stderr().is_terminal();
        Screen::decide(
            terminal,
            std::env::var_os("NO_COLOR"),
            std::env::var_os("TERM"),
            if terminal {
                asked_width(libc::STDERR_FILENO)
            } else {
                None
            },
        )
    }

    /// A pipe or a file: no style, nothing cut, exact times.
    pub const fn pipe() -> Screen {
        Screen {
            terminal: false,
            colour: false,
            width: None,
        }
    }

    /// A terminal of `width` columns, in colour or not.
    #[cfg(test)]
    pub const fn terminal(width: usize, colour: bool) -> Screen {
        Screen {
            terminal: true,
            colour,
            width: Some(width),
        }
    }

    /// The screen from what the process was given: whether its output is a terminal, the values
    /// of `NO_COLOR` and `TERM`, and the columns the terminal said, if it said any.
    fn decide(
        terminal: bool,
        no_color: Option<std::ffi::OsString>,
        term: Option<std::ffi::OsString>,
        columns: Option<usize>,
    ) -> Screen {
        if !terminal {
            return Screen::pipe();
        }
        // NO_COLOR counts when it is set and not empty, whatever its value (no-color.org).
        let no_color = no_color.is_some_and(|v| !v.is_empty());
        let dumb = term.is_some_and(|t| t == "dumb");
        Screen {
            terminal,
            colour: !no_color && !dumb,
            width: Some(columns.unwrap_or(FALLBACK_WIDTH)),
        }
    }

    /// Text in a style: on a screen with colour, opened before it and closed after it; anywhere
    /// else the text alone. The text is escaped once more first, so nothing in it can open or
    /// close a style of its own.
    pub fn paint(&self, style: Style, text: &str) -> String {
        let text = view::shown(text);
        if !self.colour || style == PLAIN || text.is_empty() {
            return text;
        }
        let mut codes: Vec<&str> = Vec::new();
        if style.bold {
            codes.push("1");
        }
        if style.dim {
            codes.push("2");
        }
        if let Some(c) = style.colour {
            codes.push(match c {
                Colour::Red => "31",
                Colour::Green => "32",
                Colour::Yellow => "33",
                Colour::Cyan => "36",
            });
        }
        format!("\u{1b}[{}m{text}\u{1b}[0m", codes.join(";"))
    }

    /// A time as this screen shows it: on a terminal, how long ago, "3 min ago" and "2 h ago" up
    /// to a day, then the day and time in the Mac's own zone, "16 Nov 05:44"; in a pipe, exact
    /// in UTC, `2026-11-16 05:44 UTC`. `now` is when the answer was made, so the text is
    /// rendered from the message alone.
    pub fn time(&self, at: i64, now: i64) -> String {
        if !self.terminal {
            return view::utc(at);
        }
        match now - at {
            age if age < 0 => local(at, now),
            age if age < 60 => "just now".to_string(),
            age if age < 3600 => format!("{} min ago", age / 60),
            age if age < 86_400 => format!("{} h ago", age / 3600),
            _ => local(at, now),
        }
    }

    /// How long something has been so, as this screen shows it: on a terminal "for 3 min",
    /// "for 2 h" up to a day, then "since 16 Nov 05:44"; in a pipe "since" the exact time.
    pub fn since(&self, at: i64, now: i64) -> String {
        if !self.terminal {
            return format!("since {}", view::utc(at));
        }
        match now - at {
            age if age < 0 => format!("since {}", local(at, now)),
            age if age < 60 => "for less than a minute".to_string(),
            age if age < 3600 => format!("for {} min", age / 60),
            age if age < 86_400 => format!("for {} h", age / 3600),
            _ => format!("since {}", local(at, now)),
        }
    }

    /// Whether this screen cuts text to fit, and to how many columns.
    pub fn fits(&self) -> Option<usize> {
        self.width
    }
}

/// The columns of the terminal on `fd` as the system gives them (`ioctl(TIOCGWINSZ)`); `None`
/// when it does not say.
fn asked_width(fd: libc::c_int) -> Option<usize> {
    // SAFETY: `ioctl` with `TIOCGWINSZ` writes only into `ws`, which lives through the call.
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let asked = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    (asked == 0 && ws.ws_col > 0).then(|| usize::from(ws.ws_col))
}

/// The day and time of `at` in the Mac's zone, "16 Nov 05:44", with the year when it is not the
/// year of `now`; exact in UTC when the system cannot convert it.
fn local(at: i64, now: i64) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let (Some((day, time)), Some((today, _))) = (view::local(at), view::local(now)) else {
        return view::utc(at);
    };
    // `YYYY-MM-DD`, as `view::local` writes it.
    let month = day
        .get(5..7)
        .and_then(|m| m.parse::<usize>().ok())
        .and_then(|m| MONTHS.get(m.wrapping_sub(1)));
    let (Some(month), Some(date)) = (month, day.get(8..10)) else {
        return view::utc(at);
    };
    let date = date.trim_start_matches('0');
    if day.get(..4) == today.get(..4) {
        format!("{date} {month} {time}")
    } else {
        format!("{date} {month} {} {time}", &day[..4])
    }
}

/// The eight basic colours this module uses, of which these four.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Colour {
    Red,
    Yellow,
    Green,
    Cyan,
}

/// A style: a colour, bold, dim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    colour: Option<Colour>,
    bold: bool,
    dim: bool,
}

/// No style.
pub const PLAIN: Style = Style {
    colour: None,
    bold: false,
    dim: false,
};
/// Critical, urgent, a failure, a headline that needs a look.
pub const RED: Style = Style {
    colour: Some(Colour::Red),
    ..PLAIN
};
/// High, a warning, "in part".
pub const YELLOW: Style = Style {
    colour: Some(Colour::Yellow),
    ..PLAIN
};
/// Done, calm.
pub const GREEN: Style = Style {
    colour: Some(Colour::Green),
    ..PLAIN
};
/// A command to run.
pub const CYAN: Style = Style {
    colour: Some(Colour::Cyan),
    ..PLAIN
};
/// Secondary text: ids, times.
pub const DIM: Style = Style { dim: true, ..PLAIN };
/// A headline, a section's label, a count.
pub const BOLD: Style = Style {
    bold: true,
    ..PLAIN
};

impl Style {
    /// The same style, bold.
    pub const fn bold(self) -> Style {
        Style { bold: true, ..self }
    }
}

/// How many columns a text that is already escaped takes on a terminal (`icu::columns`).
pub fn columns(s: &str) -> usize {
    s.chars().map(crate::icu::columns).sum()
}

/// The pieces a cut or a line break may fall between: one character, a whole escape `\u{…}` as
/// `view::shown` and `known::whole` write a hidden character, or a whole mark `\cut{<kind>
/// <length>}` where a secret was cut out (`secrets::marks`), so neither is ever left in halves.
fn units(s: &str) -> Vec<&str> {
    // In the order they begin. Each begins where a unit does: a backslash is only ever the
    // first character of a unit.
    let mut marks = crate::secrets::marks(s).into_iter().peekable();
    let mut out = Vec::new();
    let mut at = 0;
    while let Some(c) = s[at..].chars().next() {
        let rest = &s[at..];
        let escape = rest.strip_prefix("\\u{").and_then(|after| {
            let close = after.find('}')?;
            let hex = &after[..close];
            (!hex.is_empty() && hex.len() <= 6 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .then_some(3 + close + 1)
        });
        let mark = marks
            .next_if(|(start, ..)| *start == at)
            .map(|(start, end, ..)| end - start);
        let len = mark.or(escape).unwrap_or(c.len_utf8());
        out.push(&s[at..at + len]);
        at += len;
    }
    out
}

/// A text cut to `width` columns, keeping its start and ending with `…`: how a sentence is cut.
pub fn cut_end(s: &str, width: usize) -> String {
    if columns(s) <= width {
        return s.to_string();
    }
    if width == 0 {
        return String::new();
    }
    let mut out = String::new();
    let mut taken = 0;
    for u in units(s) {
        let w = columns(u);
        if taken + w > width - 1 {
            break;
        }
        out.push_str(u);
        taken += w;
    }
    out.push('…');
    out
}

/// A text cut to `width` columns, keeping its start and its end around `…`: how a path is cut.
pub fn cut_middle(s: &str, width: usize) -> String {
    if columns(s) <= width {
        return s.to_string();
    }
    if width < 3 {
        return cut_end(s, width);
    }
    // Two thirds of what is kept from the start, where a path says whose it is, and the rest
    // from the end, where it names the file.
    let keep = width - 1;
    let mut tail = keep / 3;
    let mut head = keep - tail;
    let all = units(s);
    // A name that holds a hidden character keeps the first one in sight where it can: that the
    // name holds one can itself be a sign of tampering, and a cut must not hide it.
    let escaped = |u: &&str| u.starts_with("\\u{") && u.len() > 1;
    let mut at = 0;
    let first_escape_end = all.iter().find_map(|u| {
        at += columns(u);
        escaped(u).then_some(at)
    });
    if let Some(end) = first_escape_end
        && end > head
        && end + 2 <= keep
    {
        head = end;
        tail = keep - end;
    }
    let mut start = String::new();
    let mut taken = 0;
    let mut first_tail = all.len();
    for (i, u) in all.iter().enumerate() {
        let w = columns(u);
        if taken + w > head {
            first_tail = i;
            break;
        }
        start.push_str(u);
        taken += w;
    }
    let mut end: Vec<&str> = Vec::new();
    let mut taken = 0;
    for u in all[first_tail..].iter().rev() {
        let w = columns(u);
        if taken + w > tail {
            break;
        }
        end.push(u);
        taken += w;
    }
    end.reverse();
    format!("{start}…{}", end.concat())
}

/// A text broken into lines of at most `width` columns, at spaces; a word longer than a line is
/// broken where it reaches the end, between two units, so an escape or a mark is never broken:
/// one wider than a whole line stands alone on its line. Without a width, one line.
pub fn wrap(s: &str, width: Option<usize>) -> Vec<String> {
    let Some(width) = width.map(|w| w.max(1)) else {
        return vec![s.to_string()];
    };
    // The words, split at the spaces between units: the space inside a mark splits nothing.
    let mut words: Vec<Vec<&str>> = vec![Vec::new()];
    for u in units(s) {
        match (u, words.last_mut()) {
            (" ", _) => words.push(Vec::new()),
            (_, Some(word)) => word.push(u),
            (_, None) => {}
        }
    }
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in words {
        let wide: usize = word.iter().map(|u| columns(u)).sum();
        let need = columns(&line) + usize::from(!line.is_empty()) + wide;
        if !line.is_empty() && need > width {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        // A word wider than a whole line goes in pieces.
        for u in word {
            if columns(&line) + columns(u) > width && !line.is_empty() {
                lines.push(std::mem::take(&mut line));
            }
            line.push_str(u);
        }
    }
    lines.push(line);
    lines
}

/// How a column may be cut to fit the width: never (ids, levels, counts), keeping its start (a
/// sentence), or keeping its start and its end (a path).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cut {
    Never,
    End,
    Middle,
}

/// One column of a table.
#[derive(Clone, Copy, Debug)]
pub struct Column {
    pub cut: Cut,
    /// Numbers are set to the right.
    pub right: bool,
    /// Of the columns that may be cut, one that gives more gives way first.
    pub give: u8,
}

impl Column {
    pub const fn new(cut: Cut) -> Column {
        Column {
            cut,
            right: false,
            give: 0,
        }
    }
    pub const fn right(cut: Cut) -> Column {
        Column {
            cut,
            right: true,
            give: 0,
        }
    }
    /// The same column, giving way before the columns that give less.
    pub const fn giving(self, give: u8) -> Column {
        Column { give, ..self }
    }
}

/// One cell: its text, already escaped, its style, and how many columns of its start a cut
/// keeps whole while it can, such as a package's name before the folder it is in.
#[derive(Clone, Debug)]
pub struct Cell {
    pub text: String,
    pub style: Style,
    pub keep: usize,
}

impl Cell {
    pub fn new(text: impl Into<String>, style: Style) -> Cell {
        Cell {
            text: text.into(),
            style,
            keep: 0,
        }
    }
    pub fn plain(text: impl Into<String>) -> Cell {
        Cell::new(text, PLAIN)
    }
    /// The same cell, its first `keep` columns kept whole by a cut while they leave room.
    pub fn keeping(self, keep: usize) -> Cell {
        Cell { keep, ..self }
    }
}

/// The fewest columns a column that may be cut is cut to while another can still give.
const NARROWEST: usize = 8;

/// A cell cut to `width` as its column cuts, its kept start whole while it leaves a few columns
/// for the rest.
fn cut_cell(cell: &Cell, cut: Cut, width: usize) -> String {
    let cut_rest = |s: &str, w: usize| match cut {
        Cut::Never => s.to_string(),
        Cut::End => cut_end(s, w),
        Cut::Middle => cut_middle(s, w),
    };
    if cut == Cut::Never || columns(&cell.text) <= width {
        return cell.text.clone();
    }
    let all = units(&cell.text);
    let (mut head, mut taken, mut at) = (String::new(), 0, 0);
    for u in &all {
        if taken >= cell.keep {
            break;
        }
        head.push_str(u);
        taken += columns(u);
        at += 1;
    }
    if cell.keep > 0 && taken + 6 <= width {
        let rest: String = all[at..].concat();
        format!("{head}{}", cut_rest(&rest, width - taken))
    } else {
        cut_rest(&cell.text, width)
    }
}

impl Screen {
    /// Rows in columns two spaces apart, indented by `indent`, under a head when one is given.
    /// On a terminal the columns that may be cut give way, those that give most first and the
    /// widest of them first, until every line fits the width; in a pipe nothing is cut. Lines end
    /// without trailing space.
    pub fn table(
        &self,
        indent: usize,
        columns_of: &[Column],
        head: Option<&[&str]>,
        rows: &[Vec<Cell>],
    ) -> Vec<String> {
        let n = columns_of.len();
        let mut widths = vec![0; n];
        // Escaped before it is measured or cut: what is measured is what is shown.
        let all: Vec<Vec<Cell>> = head
            .map(|h| h.iter().map(|t| Cell::new(*t, BOLD)).collect())
            .into_iter()
            .chain(rows.iter().cloned())
            .map(|row| {
                row.into_iter()
                    .map(|c| Cell {
                        text: view::shown(&c.text),
                        ..c
                    })
                    .collect()
            })
            .collect();
        for row in &all {
            for (w, cell) in widths.iter_mut().zip(row) {
                *w = (*w).max(columns(&cell.text));
            }
        }
        if let Some(width) = self.fits() {
            let used =
                |widths: &[usize]| indent + widths.iter().sum::<usize>() + 2 * n.saturating_sub(1);
            let mut gives: Vec<u8> = columns_of.iter().map(|c| c.give).collect();
            gives.sort_unstable_by(|a, b| b.cmp(a));
            gives.dedup();
            for floor in [NARROWEST, 1] {
                for give in &gives {
                    while used(&widths) > width {
                        let widest = (0..n)
                            .filter(|&i| {
                                columns_of[i].cut != Cut::Never
                                    && columns_of[i].give == *give
                                    && widths[i] > floor
                            })
                            .max_by_key(|&i| (widths[i], i));
                        let Some(i) = widest else { break };
                        widths[i] -= 1;
                    }
                }
            }
        }
        all.iter()
            .map(|row| {
                let mut line = " ".repeat(indent);
                for (i, cell) in row.iter().enumerate().take(n) {
                    let text = match self.fits() {
                        None => cell.text.clone(),
                        Some(_) => cut_cell(cell, columns_of[i].cut, widths[i]),
                    };
                    let pad = " ".repeat(widths[i].saturating_sub(columns(&text)));
                    if i > 0 {
                        line.push_str("  ");
                    }
                    let painted = self.paint(cell.style, &text);
                    if columns_of[i].right {
                        line.push_str(&pad);
                        line.push_str(&painted);
                    } else {
                        line.push_str(&painted);
                        line.push_str(&pad);
                    }
                }
                line.trim_end_matches(' ').to_string()
            })
            .collect()
    }

    /// A first line: the answer on the left in its style, and on a terminal a time dim at the
    /// right edge; where both do not fit, the time goes on a line of its own below. In a pipe
    /// the time follows the answer.
    pub fn headline(&self, answer: &str, style: Style, right: Option<&str>) -> Vec<String> {
        let (answer, right) = (view::shown(answer), right.map(view::shown));
        let right = right.as_deref();
        let mut out: Vec<String> = Vec::new();
        let lines = wrap(&answer, self.fits());
        for l in &lines {
            out.push(self.paint(style, l));
        }
        let Some(right) = right else { return out };
        match self.fits() {
            None => {
                let last = out.pop().unwrap_or_default();
                out.push(format!("{last}   {}", self.paint(DIM, right)));
            }
            Some(width) => {
                let last = lines.last().map(|l| columns(l)).unwrap_or(0);
                let r = columns(right);
                if last + 3 + r <= width {
                    let line = out.pop().unwrap_or_default();
                    out.push(format!(
                        "{line}{}{}",
                        " ".repeat(width - last - r),
                        self.paint(DIM, right)
                    ));
                } else {
                    let right = cut_end(right, width);
                    out.push(format!(
                        "{}{}",
                        " ".repeat(width.saturating_sub(columns(&right))),
                        self.paint(DIM, &right)
                    ));
                }
            }
        }
        out
    }

    /// A labelled line: the label bold in a column of `label_width` after `indent`, the value in
    /// its style beside it, and a command to run after it, cyan, where the values of its
    /// neighbours end (`value_width`). On a terminal a value that does not fit is broken into
    /// lines under itself, never cut, and the command goes on a line of its own when it would
    /// leave the value too little room.
    #[allow(clippy::too_many_arguments)]
    pub fn labelled(
        &self,
        indent: usize,
        label_width: usize,
        label: &str,
        value: &str,
        style: Style,
        command: Option<&str>,
        value_width: usize,
    ) -> Vec<String> {
        self.labelled_parts(
            indent,
            label_width,
            label,
            &[(value, style)],
            command,
            value_width,
        )
    }

    /// The same, with a value made of parts in styles of their own, such as a state and what is
    /// wrong with it. Each part is escaped before the value is measured or broken into lines.
    pub fn labelled_parts(
        &self,
        indent: usize,
        label_width: usize,
        label: &str,
        parts: &[(&str, Style)],
        command: Option<&str>,
        value_width: usize,
    ) -> Vec<String> {
        let label = &view::shown(label);
        // The style of each byte of the value, to paint each line by the parts it holds.
        let mut joined = String::new();
        let mut styles: Vec<Style> = Vec::new();
        for (text, style) in parts {
            let text = view::shown(text);
            styles.extend(std::iter::repeat_n(*style, text.len()));
            joined.push_str(&text);
        }
        let value = &joined;
        let mut cursor = 0;
        let mut paint_line = |l: &str| -> String {
            if l.is_empty() {
                return String::new();
            }
            let Some(at) = value[cursor..].find(l).map(|i| cursor + i) else {
                return self.paint(styles.first().copied().unwrap_or(PLAIN), l);
            };
            cursor = at + l.len();
            let mut painted = String::new();
            let mut run_start = 0;
            for (i, _) in l
                .char_indices()
                .skip(1)
                .chain(std::iter::once((l.len(), ' ')))
            {
                if i == l.len() || styles[at + i] != styles[at + run_start] {
                    painted.push_str(&self.paint(styles[at + run_start], &l[run_start..i]));
                    run_start = i;
                }
            }
            painted
        };
        let lead = indent + label_width + 3;
        let first_prefix = format!(
            "{}{}{}",
            " ".repeat(indent),
            self.paint(BOLD, label),
            " ".repeat(lead.saturating_sub(indent + columns(label)))
        );
        let command_width = command.map_or(0, |c| columns(c) + 4);
        let (room, beside) = match (self.fits(), command) {
            (None, _) => (None, true),
            (Some(width), None) => (Some(width.saturating_sub(lead).max(1)), true),
            (Some(width), Some(_)) => {
                let all = width.saturating_sub(lead);
                let column = value_width.min(all.saturating_sub(command_width));
                if column >= 24 {
                    (Some(column), true)
                } else if columns(value) + command_width <= all {
                    // No room for a column of commands, but this value leaves room for one.
                    (Some(columns(value).max(1)), true)
                } else {
                    (Some(all.max(1)), false)
                }
            }
        };
        let lines = if value.is_empty() {
            vec![String::new()]
        } else {
            wrap(value, room)
        };
        let mut out = Vec::new();
        for (i, l) in lines.iter().enumerate() {
            let prefix = if i == 0 {
                first_prefix.clone()
            } else {
                " ".repeat(lead)
            };
            out.push(format!("{prefix}{}", paint_line(l)));
        }
        if let Some(c) = command {
            let painted = self.paint(CYAN, c);
            match (beside, out.first_mut()) {
                (true, Some(line)) => {
                    let first = columns(&lines[0]);
                    let column = room.unwrap_or(value_width).max(first);
                    line.push_str(&" ".repeat(column - first + 4));
                    line.push_str(&painted);
                }
                _ => out.push(format!("{}{painted}", " ".repeat(lead))),
            }
        }
        out.into_iter()
            .map(|l| l.trim_end_matches(' ').to_string())
            .collect()
    }

    /// The last line: the next command after `→`, cyan, and what it does.
    pub fn next(&self, command: &str, does: &str) -> String {
        self.next_in(command, does, columns(command))
    }

    /// Next commands, each as `next` gives it, with what they do lined up over the commands
    /// whose line fits the screen; one that would not fit lined up keeps its own column.
    pub fn nexts(&self, steps: &[(&str, &str)]) -> Vec<String> {
        let fits = |command: usize, does: usize| {
            self.fits()
                .is_none_or(|width| 2 + command + 3 + does <= width)
        };
        let sizes: Vec<(usize, usize)> = steps
            .iter()
            .map(|(c, d)| (columns(c), columns(&view::shown(d))))
            .collect();
        let column = sizes
            .iter()
            .filter(|(c, d)| fits(*c, *d))
            .map(|(c, _)| *c)
            .max()
            .unwrap_or(0);
        steps
            .iter()
            .zip(&sizes)
            .map(|((c, does), (_, d))| {
                self.next_in(c, does, if fits(column, *d) { column } else { 0 })
            })
            .collect()
    }

    /// One next command, what it does starting three columns after a column of `column`.
    fn next_in(&self, command: &str, does: &str, column: usize) -> String {
        let does = &view::shown(does);
        let gap = " ".repeat(column.saturating_sub(columns(command)) + 3);
        let line = format!("→ {command}{gap}{does}");
        match self.fits() {
            Some(width) if columns(&line) > width => {
                let room = width.saturating_sub(columns(command) + 2 + gap.len());
                format!(
                    "{}{gap}{}",
                    self.paint(CYAN, &format!("→ {command}")),
                    cut_end(does, room)
                )
                .trim_end()
                .to_string()
            }
            _ => format!("{}{gap}{does}", self.paint(CYAN, &format!("→ {command}"))),
        }
    }
}

/// One line under an error, indented. `Words` are Immunity Core's own words, where a span in backticks
/// is a command, cyan on a terminal, the backticks dropped; never text from a source or from the
/// command line. `Command` is a whole command line, which may hold what the person typed, each
/// such word as the shell reads it back (`text::shell_word`): one line, never broken or cut,
/// cyan as a whole, and nothing in it is read as a mark.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    Words(String),
    Command(String),
}

/// The column the cause of an error starts in, after `error: `.
const CAUSE_AT: usize = 7;

impl Screen {
    /// A refusal or a failure as a person reads it on standard error, the one form every
    /// command gives one in: `error:` red and bold and the cause in Immunity Core's words; then,
    /// indented, what to do (`steps`); then what the failure quotes from a source or from what
    /// it was given, each under its label, escaped and never inside Immunity Core's words. Nothing
    /// else: no usage. On a terminal every part is broken into lines that fit, never cut, and a
    /// line that goes on is indented, so nothing but the first line starts at the left edge.
    pub fn error(&self, cause: &str, steps: &[Step], detail: &[(&str, &str)]) -> String {
        let room = |indent: usize| self.fits().map(|w| w.saturating_sub(indent).max(1));
        let mut out = Vec::new();
        for (i, l) in wrap(&view::shown(cause), room(CAUSE_AT)).iter().enumerate() {
            out.push(match i {
                0 => format!("{} {l}", self.paint(RED.bold(), "error:")),
                _ => format!("{}{l}", " ".repeat(CAUSE_AT)),
            });
        }
        for step in steps {
            match step {
                Step::Words(words) => {
                    for l in self.marked(words, room(2)) {
                        out.push(format!("  {l}"));
                    }
                }
                // A command is one line whatever the width: broken, its first line alone would be
                // a command that means something else. It is never cut either; it may be wider
                // than the screen.
                Step::Command(command) => {
                    out.push(format!("  {}", self.paint(CYAN, &view::shown(command))));
                }
            }
        }
        let label_width = detail.iter().map(|(l, _)| columns(l)).max().unwrap_or(0);
        for (label, value) in detail {
            out.extend(self.labelled(2, label_width, label, value, PLAIN, None, 0));
        }
        out.iter()
            .map(|l| format!("{}\n", l.trim_end_matches(' ')))
            .collect()
    }

    /// Immunity Core's own words broken into lines of `room`, each span in backticks a command in cyan
    /// with the backticks dropped. A word joined to a command, such as a comma after it, stays
    /// on its line.
    pub fn marked(&self, words: &str, room: Option<usize>) -> Vec<String> {
        // Words as the spaces part them, each in pieces of one style.
        let mut tokens: Vec<Vec<(String, Style)>> = Vec::new();
        let mut parted = true;
        for (i, segment) in view::shown(words).split('`').enumerate() {
            let style = if i % 2 == 1 { CYAN } else { PLAIN };
            for (j, piece) in segment.split(' ').enumerate() {
                parted |= j > 0;
                if piece.is_empty() {
                    continue;
                }
                match tokens.last_mut() {
                    Some(token) if !parted => token.push((piece.to_string(), style)),
                    _ => tokens.push(vec![(piece.to_string(), style)]),
                }
                parted = false;
            }
        }
        let width = |t: &[(String, Style)]| t.iter().map(|(p, _)| columns(p)).sum::<usize>();
        let mut lines: Vec<Vec<&[(String, Style)]>> = vec![Vec::new()];
        let mut taken = 0;
        for token in &tokens {
            let line = lines.last_mut().expect("a line");
            let need = width(token) + usize::from(!line.is_empty());
            if room.is_some_and(|r| !line.is_empty() && taken + need > r) {
                lines.push(vec![token]);
                taken = width(token);
            } else {
                line.push(token);
                taken += need;
            }
        }
        lines
            .iter()
            .map(|line| {
                // Runs of one style; the space between two words is plain unless both are commands.
                let mut runs: Vec<(String, Style)> = Vec::new();
                for (k, token) in line.iter().enumerate() {
                    for (n, (piece, style)) in token.iter().enumerate() {
                        if k > 0 && n == 0 {
                            match runs.last_mut() {
                                Some((run, s)) if *s == PLAIN || s == style => run.push(' '),
                                _ => runs.push((" ".to_string(), PLAIN)),
                            }
                        }
                        match runs.last_mut() {
                            Some((run, s)) if s == style => run.push_str(piece),
                            _ => runs.push((piece.clone(), *style)),
                        }
                    }
                }
                runs.iter().map(|(r, s)| self.paint(*s, r)).collect()
            })
            .collect()
    }
}

/// What a line shows on a terminal, without the style sequences this module writes, for tests.
#[cfg(test)]
pub fn visible(line: &str) -> String {
    let mut out = String::new();
    let mut rest = line;
    while let Some(at) = rest.find('\u{1b}') {
        out.push_str(&rest[..at]);
        let after = &rest[at..];
        let end = after.find('m').map_or(after.len(), |m| m + 1);
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colour_is_only_for_a_terminal_without_no_color_and_not_dumb() {
        let os = |s: &str| Some(std::ffi::OsString::from(s));
        let term = os("xterm-256color");
        assert!(Screen::decide(true, None, term.clone(), Some(100)).colour);
        // NO_COLOR set and not empty turns colour off, whatever its value; empty counts as unset.
        assert!(!Screen::decide(true, os("1"), term.clone(), Some(100)).colour);
        assert!(!Screen::decide(true, os("false"), term.clone(), Some(100)).colour);
        assert!(Screen::decide(true, os(""), term.clone(), Some(100)).colour);
        assert!(!Screen::decide(true, None, os("dumb"), Some(100)).colour);
        // A pipe has no colour and no width, whatever else is set.
        let pipe = Screen::decide(false, None, term, Some(100));
        assert_eq!(pipe, Screen::pipe());
    }

    #[test]
    fn a_terminal_that_does_not_say_its_width_is_taken_as_eighty_columns() {
        assert_eq!(Screen::decide(true, None, None, None).width, Some(80));
        assert_eq!(Screen::decide(true, None, None, Some(132)).width, Some(132));
    }

    #[test]
    fn a_style_is_closed_where_its_text_ends_and_is_written_only_with_colour() {
        let s = Screen::terminal(80, true);
        assert_eq!(s.paint(RED, "critical"), "\u{1b}[31mcritical\u{1b}[0m");
        assert_eq!(s.paint(RED.bold(), "x"), "\u{1b}[1;31mx\u{1b}[0m");
        assert_eq!(
            Screen::terminal(80, false).paint(RED, "critical"),
            "critical"
        );
        assert_eq!(Screen::pipe().paint(BOLD, "critical"), "critical");
    }

    #[test]
    fn text_handed_to_a_style_unescaped_still_cannot_open_or_close_one() {
        // A style sequence and a title sequence inside a text: written out, never sent.
        let s = Screen::terminal(80, true);
        let painted = s.paint(DIM, "a\u{1b}[31mb\u{1b}]0;t\u{7}c\u{202e}");
        assert_eq!(painted.matches('\u{1b}').count(), 2, "{painted:?}");
        assert!(
            painted.contains(r"a\u{1b}[31mb\u{1b}]0;t\u{7}c\u{202e}"),
            "{painted:?}"
        );
    }

    #[test]
    fn a_sentence_keeps_its_start_and_a_path_its_start_and_end() {
        assert_eq!(
            cut_end("Malicious package in a project", 12),
            "Malicious p…"
        );
        assert_eq!(cut_end("short", 12), "short");
        assert_eq!(
            cut_middle("~/dev/a-very-long-project-name/package-lock.json", 20),
            "~/dev/a-very-…k.json"
        );
        assert_eq!(columns(&cut_middle("~/dev/a-very-long/x.json", 9)), 9);
    }

    #[test]
    fn a_cut_never_splits_a_written_out_hidden_character() {
        let s = r"ab\u{1b}[31mcdef";
        // Ten columns would end inside `\u{1b}`: the whole escape goes instead.
        assert_eq!(cut_end(s, 5), "ab…");
        assert_eq!(cut_end(s, 9), r"ab\u{1b}…");
        let t = cut_middle(r"\u{202e}abcdefghij\u{202e}", 12);
        assert!(!t.contains(r"\u{20") || t.contains(r"\u{202e}"), "{t}");
    }

    #[test]
    fn a_line_break_or_a_cut_never_falls_inside_a_mark_where_a_secret_was_cut() {
        let mark = r"\cut{gitleaks:github-pat 40}";
        let text = format!("token {mark} end");
        // The space inside the mark is not a place to break a line.
        for width in [10, 20, 30] {
            let lines = wrap(&text, Some(width));
            assert!(lines.iter().any(|l| l.contains(mark)), "{width}: {lines:?}");
        }
        assert_eq!(
            wrap(&text, Some(31)),
            ["token", mark, "end"].map(String::from)
        );
        // A cut takes the whole mark or none of it.
        assert_eq!(cut_end(&text, 12), "token …");
    }

    #[test]
    fn wide_characters_take_two_columns_and_marks_none() {
        assert_eq!(columns("日本"), 4);
        assert_eq!(columns("e\u{301}"), 1);
        assert_eq!(columns("✓ ✗ → … ●"), 9);
        assert!(columns(&cut_end("日本語のパス", 5)) <= 5);
    }

    #[test]
    fn a_table_fits_the_terminal_by_cutting_only_the_columns_that_may_be_cut() {
        let cols = [
            Column::new(Cut::Never),
            Column::new(Cut::End),
            Column::new(Cut::Middle),
        ];
        let rows = vec![vec![
            Cell::plain("f0123456789"),
            Cell::plain("A title that is rather long for the room"),
            Cell::plain("~/dev/some-project/with/a/long/path/package-lock.json"),
        ]];
        // At 24 columns the cut columns go below their narrowest and the id still stays whole.
        for width in [24, 40, 60, 80] {
            for line in Screen::terminal(width, true).table(2, &cols, None, &rows) {
                assert!(columns(&visible(&line)) <= width, "{width}: {line}");
                assert!(line.contains("f0123456789"), "{line}");
            }
        }
        // In a pipe every cell is whole.
        let piped = Screen::pipe().table(2, &cols, None, &rows).concat();
        assert!(piped.contains("A title that is rather long for the room"));
        assert!(piped.contains("~/dev/some-project/with/a/long/path/package-lock.json"));
    }

    #[test]
    fn a_long_value_beside_its_label_is_broken_into_lines_and_never_cut() {
        let s = Screen::terminal(40, false);
        let value =
            "a watcher runs, but its latest write to the store failed, so it does not watch live";
        let lines = s.labelled(2, 8, "Watching", value, RED, Some("immunity on"), 30);
        for l in &lines {
            assert!(columns(l) <= 40, "{l}");
        }
        let joined: Vec<&str> = lines.iter().map(|l| l.trim()).collect();
        let joined = joined.join(" ");
        assert!(joined.contains("does not watch live"), "{joined}");
        assert!(joined.contains("immunity on"), "{joined}");
    }

    #[test]
    fn an_error_is_its_cause_then_what_to_do_then_what_it_quotes_and_nothing_else() {
        let steps = [
            Step::Words("Nothing was done. See it with: `immunity status`".to_string()),
            Step::Command("immunity finding f0123456789 expected --reason <text>".to_string()),
        ];
        let said = Screen::pipe().error("a cause", &steps, &[("Store", "/x/store.db")]);
        assert_eq!(
            said,
            "error: a cause\n  Nothing was done. See it with: immunity status\n  \
             immunity finding f0123456789 expected --reason <text>\n  Store   /x/store.db\n"
        );
        let painted = Screen::terminal(80, true).error("a cause", &steps, &[]);
        let lines: Vec<&str> = painted.lines().collect();
        assert_eq!(lines[0], "\u{1b}[1;31merror:\u{1b}[0m a cause");
        assert_eq!(
            lines[1],
            "  Nothing was done. See it with: \u{1b}[36mimmunity status\u{1b}[0m"
        );
        assert!(
            lines[2].starts_with("  \u{1b}[36mimmunity finding"),
            "{painted}"
        );
    }

    #[test]
    fn an_error_on_a_narrow_terminal_is_broken_into_lines_that_fit_and_never_cut() {
        let cause = "the event log could not be read, so nothing was evaluated at all today";
        let path = "/Users/example/Library/Application Support/ai.nuanu.immunity.core/a-very-long-folder/store.db";
        let s = Screen::terminal(40, false);
        let said = s.error(
            cause,
            &[Step::Words(
                "It was left unchanged. Move it aside or pass another --store.".to_string(),
            )],
            &[("Store", path)],
        );
        let mut words = String::new();
        for (i, l) in said.lines().enumerate() {
            assert!(columns(l) <= 40, "{l}");
            // Only the first line starts at the left edge.
            assert_eq!(l.starts_with(' '), i > 0, "{said}");
            words.push_str(&l.replace(' ', ""));
        }
        assert!(words.contains(&path.replace(' ', "")), "{said}");
        assert!(words.contains("evaluatedatalltoday"), "{said}");
    }

    #[test]
    fn a_command_under_an_error_is_one_line_at_any_width_never_broken_or_cut() {
        let command = "immunity finding f0123456789 seen --reason checked --via app \
                       --journal-seq 3 --store /Users/example/.immunity/store.db";
        for width in [40, 60, 80] {
            let said = Screen::terminal(width, false).error(
                "a cause",
                &[Step::Command(command.to_string())],
                &[],
            );
            let lines: Vec<&str> = said.lines().collect();
            assert_eq!(lines.len(), 2, "{width}: {said}");
            assert_eq!(lines[1], format!("  {command}"), "{width}");
        }
    }

    #[test]
    fn a_word_joined_to_a_command_stays_on_its_line_and_takes_no_colour() {
        let lines = Screen::terminal(80, true).marked("Run `immunity run`, then wait.", None);
        assert_eq!(lines, ["Run \u{1b}[36mimmunity run\u{1b}[0m, then wait."]);
        assert_eq!(
            Screen::pipe().marked("Run `immunity run`, then wait.", Some(12)),
            ["Run immunity", "run, then", "wait."]
        );
    }

    #[test]
    fn times_are_relative_on_a_terminal_and_exact_in_a_pipe() {
        let now = 1_794_807_960;
        let t = Screen::terminal(80, false);
        assert_eq!(t.time(now - 20, now), "just now");
        assert_eq!(t.time(now - 180, now), "3 min ago");
        assert_eq!(t.time(now - 7300, now), "2 h ago");
        // Past a day, the day and time; the zone is the Mac's, so only the shape is fixed.
        let day = t.time(now - 3 * 86_400, now);
        assert!(day.contains(" Nov ") && day.contains(':'), "{day}");
        assert_eq!(Screen::pipe().time(now - 180, now), view::utc(now - 180));
    }
}
