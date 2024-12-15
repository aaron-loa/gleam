#[derive(Debug, serde::Serialize, serde::Deserialize, Clone, PartialEq, Eq)]
pub struct LineNumbers {
    pub line_starts: Vec<u32>,
    pub length: u32,
}

impl LineNumbers {
    pub fn new(src: &str) -> Self {
        Self {
            length: src.len() as u32,
            line_starts: std::iter::once(0)
                .chain(src.match_indices('\n').map(|(i, _)| i as u32 + 1))
                .collect(),
        }
    }

    /// Get the line number for a byte index
    pub fn line_number(&self, byte_index: u32) -> u32 {
        self.line_starts
            .binary_search(&byte_index)
            .unwrap_or_else(|next_line| next_line - 1) as u32
            + 1
    }

    /// Will return the line and utf-16 column number for a byte index
    pub fn line_and_column_number(&self, byte_index: u32, src: &str) -> LineColumn {
        let line = self.line_number(byte_index);
        let column = byte_index
            - self
                .line_starts
                .get(line as usize - 1)
                .copied()
                .unwrap_or_default()
            + 1;

        let utf16_column = self.get_utf16_index_in_line(src, line - 1, column as usize - 1) + 1;
        LineColumn {
            line,
            column: utf16_column,
        }
    }

    /// Will return the line and byte index column number for a byte index
    pub fn line_and_column_number_direct(&self, byte_index: u32) -> LineColumn {
        let line = self.line_number(byte_index);
        let column = byte_index
            - self
                .line_starts
                .get(line as usize - 1)
                .copied()
                .unwrap_or_default()
            + 1;
        LineColumn { line, column }
    }

    // TODO: handle unicode characters that may be more than 1 byte in width
    /// 0 indexed line and character to byte index
    pub fn byte_index(&self, line: u32, character: u32, src: &str) -> u32 {
        match self.line_starts.get((line) as usize) {
            Some(line_index) => {
                return *line_index + self.get_utf16_index_in_line(src, line, character as usize);
            }
            None => self.length,
        }
    }

    pub fn byte_index_direct(&self, line: u32, character: u32) -> u32 {
        match self.line_starts.get((line) as usize) {
            Some(line_index) => *line_index + character,
            None => self.length,
        }
    }

    fn get_utf16_index_in_line(&self, src: &str, line: u32, column: usize) -> u32 {
        let line_beginning = self.byte_index_direct(line, 0);
        let line_ending = self.byte_index_direct(line + 1, 0);
        let line = &src[line_beginning as usize..line_ending as usize];
        return self.direct_index_to_utf16_index(line, column);
    }

    fn direct_index_to_utf16_index(&self, src: &str, byte_index: usize) -> u32 {
        let mut utf16_index = 0;
        for (idx, char) in src.char_indices() {
            if idx + char.len_utf8() > byte_index || idx == byte_index {
                break;
            }
            utf16_index += char.len_utf16() as u32;
        }
        return utf16_index;
    }
}

#[test]
fn byte_index() {
    let src = &r#"import gleam/io

pub fn main() {
  io.println("Hello, world!")
}
"#;
    let line_numbers = LineNumbers::new(src);

    assert_eq!(line_numbers.byte_index(0, 0, *src), 0);
    assert_eq!(line_numbers.byte_index(0, 4, *src), 4);
    assert_eq!(line_numbers.byte_index(100, 1, *src), src.len() as u32);
    assert_eq!(line_numbers.byte_index(2, 1, src), 18);
}

#[derive(Debug, Clone, Copy)]
pub struct LineColumn {
    pub line: u32,
    pub column: u32,
}
