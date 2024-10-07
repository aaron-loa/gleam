mod code_action;
mod compiler;
mod completer;
mod edits;
mod engine;
mod feedback;
mod files;
mod messages;
mod progress;
mod router;
mod server;
mod signature_help;

#[cfg(test)]
mod tests;

use capnp::io::Write;
pub use server::LanguageServer;

use crate::{
    ast::SrcSpan, build::Target, line_numbers::LineNumbers, manifest::Manifest,
    paths::ProjectPaths, Result,
};
use camino::Utf8PathBuf;
use lsp_types::{Position, Range, Url};
use std::any::Any;

#[derive(Debug)]
pub struct LockGuard(pub Box<dyn Any>);

pub trait Locker {
    fn lock_for_build(&self) -> LockGuard;
}

pub trait MakeLocker {
    fn make_locker(&self, paths: &ProjectPaths, target: Target) -> Result<Box<dyn Locker>>;
}

pub trait DownloadDependencies {
    fn download_dependencies(&self, paths: &ProjectPaths) -> Result<Manifest>;
}

/// If src string is provided, the range will be adjusted to UTF-16 positions
pub fn src_span_to_lsp_range(
    location: SrcSpan,
    line_numbers: &LineNumbers,
    src: Option<&str>,
) -> Range {
    let mut start = line_numbers.line_and_column_number(location.start);
    let mut end = line_numbers.line_and_column_number(location.end);
    let mut log_file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .open("/home/ron/programs/gleam/lsp-log.txt")
        .unwrap();

    log_file
        .write_all(format!("\n\nlocation: {:?}\n", location).as_bytes())
        .unwrap();
    log_file
        .write_all(format!("\n\ntext: {:?}\n", src.unwrap_or(&"hello")).as_bytes())
        .unwrap();
    log_file
        .write_all(format!("start: {:?}\n", start).as_bytes())
        .unwrap();
    log_file
        .write_all(format!("end: {:?}\n", end).as_bytes())
        .unwrap();

    if let Some(src) = src {
        // To get the correct ranges, we need to get the UTF-16 positions
        // relative to the line the start and end positions are
        start.column = get_utf16_index_in_line(
            src,
            start.line - 1,
            start.column as usize,
            line_numbers,
            &mut log_file,
        );

        end.column = get_utf16_index_in_line(
            src,
            end.line - 1,
            end.column as usize,
            line_numbers,
            &mut log_file,
        );

        if start.column == end.column
            && start.line == end.line
            && location.end - location.start == 1
        {
            end.column += 1;
        }
    }

    log_file
        .write_all(format!("after\nstart: {:?}\n", start).as_bytes())
        .unwrap();
    log_file
        .write_all(format!("end: {:?}\n", end).as_bytes())
        .unwrap();
    Range::new(
        Position::new(start.line - 1, start.column - 1),
        Position::new(end.line - 1, end.column - 1),
    )
}

pub fn get_utf16_index_in_line(
    src: &str,
    line: u32,
    column: usize,
    line_numbers: &LineNumbers,
    file: &mut std::fs::File,
) -> u32 {
    let line_beginning = line_numbers.byte_index(line, 0);
    let line_ending = line_numbers.byte_index(line + 1, 0);
    let line = &src[line_beginning as usize..line_ending as usize];
    file.write_all(format!("line_beginning: {:?}\n", line_beginning).as_bytes())
        .unwrap();
    file.write_all(format!("line_ending: {:?}\n", line_ending).as_bytes())
        .unwrap();
    file.write_all(format!("line: {:?}\n", line).as_bytes())
        .unwrap();
    return utf8_index_to_utf16_index(line, column, file);
}

fn utf8_index_to_utf16_index(src: &str, byte_index: usize, file: &mut std::fs::File) -> u32 {
    let mut utf16_index = 0;
    for (idx, char) in src.char_indices() {
        file.write_all(format!("idx: {:?} {:?}\n", idx, char).as_bytes())
            .unwrap();
        if idx + char.len_utf8() > byte_index || idx == byte_index {
            file.write_all(format!("break\n").as_bytes()).unwrap();
            break;
        }
        utf16_index += char.len_utf16() as u32;
        file.write_all(format!("increased\n").as_bytes()).unwrap();
    }
    return utf16_index;
}

fn path(uri: &Url) -> Utf8PathBuf {
    // The to_file_path method is available on these platforms
    #[cfg(any(unix, windows, target_os = "redox", target_os = "wasi"))]
    return Utf8PathBuf::from_path_buf(uri.to_file_path().expect("URL file"))
        .expect("Non Utf8 Path");

    #[cfg(not(any(unix, windows, target_os = "redox", target_os = "wasi")))]
    return Utf8PathBuf::from_path_buf(uri.path().into()).expect("Non Utf8 Path");
}
