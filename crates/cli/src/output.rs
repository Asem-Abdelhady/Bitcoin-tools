//! The one place that decides what a command's result looks like.
//!
//! # The two modes are one value
//!
//! A command returns a single type that implements [`Output`]. `Serialize` on
//! that type *is* the `--json` contract, and [`Output::render`] is the terminal
//! one. They cannot describe different things because they are two views of one
//! struct: a field added to it appears in the JSON the moment it exists, and
//! `render` cannot print a field the struct does not have.
//!
//! That is deliberate. The ordinary way a CLI goes wrong is a `--json` mode
//! bolted on beside a `println!` that has since grown a field, and no test
//! catches it because both modes pass their own assertions. Here there is one
//! value and one place — [`Context::emit`] — that chooses how to write it.

use std::fmt;
use std::io::{self, BufWriter, Write};

use serde::Serialize;

/// Which of the two output modes a run is in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Aligned, optionally coloured text for a person.
    Human,
    /// Pretty-printed JSON for a machine.
    Json,
}

/// What every command produces.
///
/// See [the module note](self) for why both halves live on one type.
pub trait Output: Serialize {
    /// Write the human-readable form.
    ///
    /// `w` is an [`anstream`] stream, so styling written here is stripped
    /// automatically when the destination is not a terminal. Do not check for a
    /// TTY yourself.
    fn render(&self, w: &mut dyn Write) -> io::Result<()>;
}

/// Everything a command needs to know about how to answer.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    format: Format,
}

impl Context {
    /// Build a context for the requested format.
    #[must_use]
    pub const fn new(format: Format) -> Self {
        Context { format }
    }

    /// Write a command's result to stdout in whichever mode was asked for.
    ///
    /// This is the **only** thing in the crate that writes to stdout, which is
    /// what makes `--json` mode's contract — nothing on stdout but JSON — a
    /// property of the code rather than a rule to remember.
    ///
    /// # Errors
    ///
    /// Whatever writing to stdout produced. A closed pipe arrives here as an
    /// ordinary [`io::Error`] and is recognised by [`crate::is_broken_pipe`],
    /// which is why the JSON arm below is careful to keep the original error
    /// reachable rather than wrapping it in a new one.
    pub fn emit<T: Output>(self, value: &T) -> io::Result<()> {
        // Buffered over a locked handle. `anstream::stdout().lock()` is a
        // `LineWriter`, so without this a hundred-key object is a hundred write
        // syscalls, and pretty-printed JSON is one per field.
        let mut out = BufWriter::new(anstream::stdout().lock());

        match self.format {
            Format::Json => {
                // `io::Error::from` and not `io::Error::other`: serde_json's
                // conversion unwraps a write failure back into the io error it
                // started as, preserving its kind. Wrapping it instead put the
                // `BrokenPipe` behind a `source()` that does not report it, so
                // `… --json | head` printed a spurious "error: Broken pipe" and
                // exited 1 — in the mode most likely to be piped.
                serde_json::to_writer_pretty(&mut out, value).map_err(io::Error::from)?;
                // Pretty-printing does not terminate the last line, and a shell
                // prompt on the same line as `}` looks like a bug.
                out.write_all(b"\n")?;
            }
            Format::Human => value.render(&mut out)?,
        }

        out.flush()
    }
}

/// The label style for human output: dimmed, so the values are what the eye
/// lands on. One constant, so every command's output looks like one program's.
const LABEL: anstyle::Style = anstyle::Style::new().dimmed();

/// The heading style: bold, for the name of a nested block.
const HEADING: anstyle::Style = anstyle::Style::new().bold();

/// How far one level of nesting moves a label to the right.
const INDENT: usize = 2;

/// One line of a [`Fields`] block.
#[derive(Debug)]
enum Row {
    /// `label  value`, at a nesting depth.
    Field {
        depth: usize,
        label: String,
        value: String,
    },
    /// The name of the block that follows.
    Heading { depth: usize, text: String },
    /// A separator.
    Blank,
}

/// A block of `label  value` rows, aligned on the longest label.
///
/// Collected before writing because the column width is not known until the
/// last row is added. Every command renders through this, so alignment and
/// styling are decided once rather than per command.
///
/// # Nesting is a depth, not a nested block
///
/// An address has parts and a derived key has an address, so the output has
/// structure — but rendering each level as its own `Fields` would align each
/// level on its own longest label, and the columns would step in and out down
/// the page. One block holding a depth per row aligns *everything* on one
/// column, which is what makes a deep output scannable.
#[derive(Debug, Default)]
pub struct Fields {
    rows: Vec<Row>,
}

impl Fields {
    /// An empty block.
    #[must_use]
    pub fn new() -> Self {
        Fields::default()
    }

    /// Add a top-level row. Chainable.
    pub fn row(&mut self, label: &str, value: impl fmt::Display) -> &mut Self {
        self.nested(0, label, value)
    }

    /// Add a row `depth` levels in. Chainable.
    pub fn nested(&mut self, depth: usize, label: &str, value: impl fmt::Display) -> &mut Self {
        self.rows.push(Row::Field {
            depth,
            label: label.to_owned(),
            value: value.to_string(),
        });
        self
    }

    /// Add a row only when there is one, so an absent value is absent rather
    /// than printed as `None`.
    ///
    /// The JSON says `null` and this says nothing, which is the one place the
    /// two modes are allowed to differ: a `null` is a fact a parser needs and a
    /// blank line is noise a reader does not.
    pub fn maybe(
        &mut self,
        depth: usize,
        label: &str,
        value: Option<impl fmt::Display>,
    ) -> &mut Self {
        match value {
            Some(value) => self.nested(depth, label, value),
            None => self,
        }
    }

    /// Name the block that follows, `depth` levels in. Chainable.
    pub fn heading(&mut self, depth: usize, text: impl fmt::Display) -> &mut Self {
        self.rows.push(Row::Heading {
            depth,
            text: text.to_string(),
        });
        self
    }

    /// A separator line. Chainable.
    pub fn blank(&mut self) -> &mut Self {
        self.rows.push(Row::Blank);
        self
    }

    /// Write every row, aligned.
    ///
    /// # Errors
    ///
    /// Whatever `w` produced.
    pub fn write(&self, w: &mut dyn Write) -> io::Result<()> {
        // Characters, not bytes. Every label is ASCII today, but this is a
        // domain whose own units include `µBTC`, and a byte count would
        // misalign the column the moment one reaches a label.
        //
        // Indentation counts toward the width, so a nested label and a
        // top-level one put their values in the same column.
        let width = self
            .rows
            .iter()
            .filter_map(|row| match row {
                Row::Field { depth, label, .. } => Some(depth * INDENT + label.chars().count()),
                _ => None,
            })
            .max()
            .unwrap_or(0);

        for row in &self.rows {
            match row {
                Row::Field {
                    depth,
                    label,
                    value,
                } => {
                    let used = depth * INDENT + label.chars().count();
                    writeln!(
                        w,
                        "{}{}{label}{}{}  {value}",
                        " ".repeat(depth * INDENT),
                        LABEL.render(),
                        LABEL.render_reset(),
                        " ".repeat(width - used)
                    )?;
                }
                Row::Heading { depth, text } => writeln!(
                    w,
                    "{}{}{text}{}",
                    " ".repeat(depth * INDENT),
                    HEADING.render(),
                    HEADING.render_reset()
                )?,
                Row::Blank => writeln!(w)?,
            }
        }

        Ok(())
    }
}

/// A grid with a header row, for a list of things that share a shape.
///
/// Separate from [`Fields`] rather than a mode of it: a script's instructions
/// and a transaction's inputs are *many of one thing*, and rendering them as
/// label/value pairs repeats every label once per row. A table names each
/// column once.
#[derive(Debug)]
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    /// A table with these column names.
    #[must_use]
    pub fn new(headers: &[&str]) -> Self {
        Table {
            headers: headers.iter().map(|h| (*h).to_owned()).collect(),
            rows: Vec::new(),
        }
    }

    /// Add a row. Chainable.
    ///
    /// A row with the wrong number of cells is not rejected — it is padded or
    /// left short by [`write`](Table::write), because a misaligned table is a
    /// better failure for a person than no output at all.
    pub fn row(&mut self, cells: Vec<String>) -> &mut Self {
        self.rows.push(cells);
        self
    }

    /// Write the header and every row, each column aligned to its widest cell.
    ///
    /// The last column is not padded: trailing spaces are invisible, survive a
    /// copy-paste, and break a `diff`.
    ///
    /// # Errors
    ///
    /// Whatever `w` produced.
    pub fn write(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.chars().count()).collect();

        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                let width = cell.chars().count();
                match widths.get_mut(i) {
                    Some(current) => *current = (*current).max(width),
                    None => widths.push(width),
                }
            }
        }

        write_cells(w, &self.headers, &widths, LABEL)?;
        for row in &self.rows {
            write_cells(w, row, &widths, anstyle::Style::new())?;
        }

        Ok(())
    }
}

/// One line of a [`Table`], padded to the column widths.
///
/// The line is assembled and then trimmed on the right rather than each cell
/// deciding whether it is last: a trailing *empty* cell would otherwise leave
/// the padding of the cell before it hanging off the end, which is how a
/// script with no data pushes ended up with three trailing spaces per row.
fn write_cells(
    w: &mut dyn Write,
    cells: &[String],
    widths: &[usize],
    style: anstyle::Style,
) -> io::Result<()> {
    let mut line = String::new();

    for (i, cell) in cells.iter().enumerate() {
        if i > 0 {
            line.push_str("  ");
        }
        line.push_str(cell);

        let width = widths.get(i).copied().unwrap_or(0);
        line.push_str(&" ".repeat(width.saturating_sub(cell.chars().count())));
    }

    writeln!(
        w,
        "{}{}{}",
        style.render(),
        line.trim_end(),
        style.render_reset()
    )
}

/// `yes` or `no`, for a boolean field in human output.
///
/// `true`/`false` is how the JSON says it and reads as debug output in a
/// terminal; the two modes are allowed to spell one value differently, so long
/// as they never disagree about what it is.
#[must_use]
pub const fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Render a block and strip the styling from it.
    ///
    /// `anstyle` writes escape codes unconditionally; it is `anstream`, one
    /// layer out, that drops them when the destination is not a terminal. A
    /// test writing into a `Vec` therefore sees them — and they contain
    /// *digits* (`\x1b[2m`), so a column position measured over the raw bytes
    /// is measuring the wrong thing. Every assertion below is about what
    /// reaches the screen, so it is made against this.
    fn plain(render: impl FnOnce(&mut dyn Write) -> io::Result<()>) -> String {
        let mut out = Vec::new();
        render(&mut out).expect("a Vec does not fail to write");
        let text = String::from_utf8(out).expect("output is UTF-8");

        let mut plain = String::new();
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // A CSI sequence: `\x1b[`, parameters, then a letter.
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                plain.push(c);
            }
        }
        plain
    }

    /// A non-ASCII label aligns by what is on screen, not by how many bytes it
    /// took. `µ` is two bytes and one column.
    #[test]
    fn a_non_ascii_label_does_not_misalign_the_column() {
        let text = plain(|w| Fields::new().row("µBTC", 1).row("sat", 2).write(w));
        let columns: Vec<usize> = text
            .lines()
            // Characters, not bytes: `µ` is two bytes and one column, which
            // is the whole point of the test.
            .map(|line| line.chars().position(char::is_numeric).unwrap())
            .collect();

        assert_eq!(
            columns[0], columns[1],
            "values start in one column:\n{text}"
        );
    }

    /// Indentation is part of the label's width, so a nested row and a
    /// top-level one put their values in the same column. Aligning each depth
    /// separately is the thing this rules out.
    #[test]
    fn a_nested_row_shares_the_column_with_a_top_level_one() {
        let text = plain(|w| {
            Fields::new()
                .row("network", 1)
                .heading(1, "addresses")
                .nested(2, "hrp", 2)
                .write(w)
        });
        let columns: Vec<usize> = text
            .lines()
            .filter_map(|line| line.chars().position(char::is_numeric))
            .collect();

        assert_eq!(columns.len(), 2, "two value rows:\n{text}");
        assert_eq!(columns[0], columns[1], "one column:\n{text}");
    }

    /// An absent value prints nothing rather than `None`.
    #[test]
    fn an_absent_value_is_absent_rather_than_printed() {
        let text = plain(|w| {
            Fields::new()
                .maybe(0, "present", Some(1))
                .maybe(0, "absent", None::<u8>)
                .write(w)
        });
        assert!(text.contains("present"), "{text}");
        assert!(!text.contains("absent"), "{text}");
        assert!(!text.contains("None"), "{text}");
    }

    /// The last column carries no padding: trailing spaces are invisible and
    /// survive into whatever the output is pasted into.
    #[test]
    fn a_table_leaves_no_trailing_whitespace() {
        let text = plain(|w| {
            Table::new(["offset", "opcode", "data"].as_slice())
                // The last cell is empty, which is the ordinary case: most
                // opcodes push nothing. The padding of the column before it is
                // what used to hang off the end of the line.
                .row(vec!["0".to_owned(), "OP_DUP".to_owned(), String::new()])
                .row(vec!["1".to_owned(), "OP_HASH160".to_owned(), String::new()])
                .row(vec![
                    "2".to_owned(),
                    "OP_PUSHBYTES_20".to_owned(),
                    "ab".to_owned(),
                ])
                .write(w)
        });
        for line in text.lines() {
            assert_eq!(line, line.trim_end(), "trailing space:\n{text:?}");
        }
    }

    /// The header and every row put a column in the same place.
    #[test]
    fn a_table_aligns_its_columns() {
        let text = plain(|w| {
            Table::new(["a", "bbbb"].as_slice())
                .row(vec!["cccc".to_owned(), "d".to_owned()])
                .write(w)
        });
        let starts: Vec<usize> = text
            .lines()
            .map(|line| {
                let last = line.rsplit("  ").next().unwrap_or(line);
                line.chars().count() - last.chars().count()
            })
            .collect();

        assert_eq!(starts[0], starts[1], "second column:\n{text}");
    }
}
