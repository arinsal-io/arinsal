//! `{line, N}` port output splitting.
//! Port of erts/emulator/beam/io.c:3138-3300 (LineBuf, read_linebuf, flush_linebuf), OTP-29.1.1.

const MAIN: u8 = 0;
const FULL: u8 = 1;
const CR_INSIDE: u8 = 2;
const CR_AFTER: u8 = 3;

/// One delivered chunk: the line bytes and whether a newline ended it.
pub(crate) type Line = (Vec<u8>, bool);

pub(crate) struct LineBuf {
    bufsiz: usize,
    state: u8,
    data: Vec<u8>,
}

impl LineBuf {
    pub(crate) fn new(bufsiz: usize) -> LineBuf {
        LineBuf {
            bufsiz,
            state: MAIN,
            data: Vec::new(),
        }
    }

    /// Port of io.c:3246 (read_linebuf), repeated until LINEBUF_EMPTY.
    pub(crate) fn read(&mut self, mut buf: &[u8]) -> Vec<Line> {
        let mut out = Vec::new();
        loop {
            let Some(&byte) = buf.first() else {
                return out;
            };
            if byte == b'\n' {
                self.state = MAIN;
                buf = &buf[1..];
                out.push((std::mem::take(&mut self.data), true));
                continue;
            }
            match self.state {
                MAIN => {
                    if self.data.len() == self.bufsiz {
                        self.state = FULL;
                    } else if byte == b'\r' {
                        buf = &buf[1..];
                        self.state = CR_INSIDE;
                    } else {
                        self.data.push(byte);
                        buf = &buf[1..];
                    }
                }
                FULL => {
                    if byte == b'\r' {
                        buf = &buf[1..];
                        self.state = CR_AFTER;
                    } else {
                        out.push((std::mem::take(&mut self.data), false));
                        self.state = MAIN;
                    }
                }
                CR_INSIDE => {
                    self.data.push(b'\r');
                    self.state = MAIN;
                }
                _ => {
                    out.push((std::mem::take(&mut self.data), false));
                    self.state = CR_INSIDE;
                }
            }
        }
    }

    /// Port of io.c:3190 (flush_linebuf), repeated until LINEBUF_EMPTY.
    pub(crate) fn flush(&mut self) -> Vec<Line> {
        let mut out = Vec::new();
        loop {
            match self.state {
                CR_INSIDE => {
                    self.data.push(b'\r');
                    self.state = MAIN;
                    out.push((std::mem::take(&mut self.data), false));
                }
                CR_AFTER => {
                    self.state = CR_INSIDE;
                    if self.data.is_empty() {
                        return out;
                    }
                    out.push((std::mem::take(&mut self.data), false));
                }
                _ => {
                    self.state = MAIN;
                    if !self.data.is_empty() {
                        out.push((std::mem::take(&mut self.data), false));
                    }
                    return out;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LineBuf;

    #[test]
    fn splits_lines_and_overlong_chunks() {
        let mut lb = LineBuf::new(3);
        let lines = lb.read(b"ab\r\nabcdef\nx");
        assert_eq!(
            lines,
            vec![
                (b"ab".to_vec(), true),
                (b"abc".to_vec(), false),
                (b"def".to_vec(), true)
            ]
        );
        assert_eq!(lb.flush(), vec![(b"x".to_vec(), false)]);
        assert!(lb.flush().is_empty());
    }
}
