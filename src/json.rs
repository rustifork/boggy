//! Tiny JSON reader/writer. No dependencies, strict input limits, no panics on bad data.

use std::fmt::Write as _;

const MAX_DEPTH: usize = 64;
const MAX_NODES: usize = 200_000;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj(fields: Vec<(&str, Json)>) -> Json {
        Json::Obj(
            fields
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
        )
    }

    pub fn arr(values: Vec<Json>) -> Json {
        Json::Arr(values)
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    pub fn opt_str(s: Option<&str>) -> Json {
        match s {
            Some(v) => Json::Str(v.to_string()),
            None => Json::Null,
        }
    }

    pub fn num(n: f64) -> Json {
        Json::Num(n)
    }

    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn string(&self) -> String {
        self.as_str().unwrap_or("").to_string()
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_obj(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Obj(o) => Some(o),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Num(n) if n.is_finite() && *n >= 0.0 && n.fract() == 0.0 => Some(*n as u64),
            _ => None,
        }
    }

    pub fn compact(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, None, 0);
        out
    }

    pub fn pretty(&self) -> String {
        let mut out = String::new();
        self.write(&mut out, Some(2), 0);
        out.push('\n');
        out
    }

    fn write(&self, out: &mut String, indent: Option<usize>, depth: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Num(n) => {
                if n.fract() == 0.0 && n.abs() < 9e15 {
                    let _ = write!(out, "{}", *n as i64);
                } else {
                    let _ = write!(out, "{}", n);
                }
            }
            Json::Str(s) => write_string(out, s),
            Json::Arr(values) => {
                out.push('[');
                for (i, v) in values.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline(out, indent, depth + 1);
                    v.write(out, indent, depth + 1);
                }
                if !values.is_empty() {
                    newline(out, indent, depth);
                }
                out.push(']');
            }
            Json::Obj(fields) => {
                out.push('{');
                for (i, (k, v)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline(out, indent, depth + 1);
                    write_string(out, k);
                    out.push(':');
                    if indent.is_some() {
                        out.push(' ');
                    }
                    v.write(out, indent, depth + 1);
                }
                if !fields.is_empty() {
                    newline(out, indent, depth);
                }
                out.push('}');
            }
        }
    }
}

fn newline(out: &mut String, indent: Option<usize>, depth: usize) {
    if let Some(width) = indent {
        out.push('\n');
        for _ in 0..depth * width {
            out.push(' ');
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

pub fn parse(data: &[u8]) -> Result<Json, String> {
    let mut p = Parser {
        data,
        pos: 0,
        depth: 0,
        nodes: 0,
    };
    p.ws();
    let value = p.value()?;
    p.ws();
    if p.pos != data.len() {
        return Err(format!("trailing data at byte {}", p.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
    nodes: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.pos < self.data.len()
            && matches!(self.data[self.pos], b' ' | b'\t' | b'\n' | b'\r')
        {
            self.pos += 1;
        }
    }

    fn bump(&mut self) -> Result<u8, String> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or_else(|| "unexpected end of JSON".to_string())?;
        self.pos += 1;
        Ok(b)
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        if self.bump()? != b {
            Err(format!("expected '{}' at byte {}", b as char, self.pos - 1))
        } else {
            Ok(())
        }
    }

    fn node(&mut self) -> Result<(), String> {
        self.nodes += 1;
        if self.nodes > MAX_NODES {
            return Err("JSON has too many nodes".into());
        }
        Ok(())
    }

    fn value(&mut self) -> Result<Json, String> {
        self.node()?;
        self.ws();
        match self.data.get(self.pos).copied() {
            Some(b'n') => {
                self.literal(b"null")?;
                Ok(Json::Null)
            }
            Some(b't') => {
                self.literal(b"true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Ok(Json::Bool(false))
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b) => Err(format!("unexpected byte '{}' at {}", b as char, self.pos)),
            None => Err("unexpected end of JSON".into()),
        }
    }

    fn literal(&mut self, word: &[u8]) -> Result<(), String> {
        if self.data.get(self.pos..self.pos + word.len()) == Some(word) {
            self.pos += word.len();
            Ok(())
        } else {
            Err(format!("invalid literal at byte {}", self.pos))
        }
    }

    fn string(&mut self) -> Result<String, String> {
        self.expect(b'"')?;
        let mut out = String::new();
        loop {
            let b = self.bump()?;
            match b {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.bump()?;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{08}'),
                        b'f' => out.push('\u{0c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let code = self.hex4()?;
                            let ch = if (0xd800..=0xdbff).contains(&code) {
                                let low = self.hex4()?;
                                if !(0xdc00..=0xdfff).contains(&low) {
                                    return Err("invalid unicode surrogate pair".into());
                                }
                                0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00)
                            } else {
                                code
                            };
                            out.push(char::from_u32(ch).ok_or("invalid unicode escape")?);
                        }
                        _ => return Err(format!("invalid escape '{}'", e as char)),
                    }
                }
                0..=0x1f => return Err("control character in string".into()),
                _ => {
                    let start = self.pos - 1;
                    let len = utf8_len(b).ok_or("invalid UTF-8 in JSON string")?;
                    if start + len > self.data.len() {
                        return Err("truncated UTF-8 in JSON string".into());
                    }
                    let s = std::str::from_utf8(&self.data[start..start + len])
                        .map_err(|_| "invalid UTF-8 in JSON string".to_string())?;
                    out.push_str(s);
                    self.pos = start + len;
                }
            }
            if out.len() > 16_384 {
                return Err("JSON string too long".into());
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let mut value = 0u32;
        for _ in 0..4 {
            let b = self.bump()?;
            let digit = (b as char)
                .to_digit(16)
                .ok_or_else(|| "invalid unicode escape".to_string())?;
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.data.get(self.pos) == Some(&b'-') {
            self.pos += 1;
        }
        match self.data.get(self.pos) {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.data.get(self.pos), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(format!("invalid number at byte {}", start)),
        }
        if self.data.get(self.pos) == Some(&b'.') {
            self.pos += 1;
            if !matches!(self.data.get(self.pos), Some(b'0'..=b'9')) {
                return Err("invalid number fraction".into());
            }
            while matches!(self.data.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.data.get(self.pos), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.data.get(self.pos), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.data.get(self.pos), Some(b'0'..=b'9')) {
                return Err("invalid number exponent".into());
            }
            while matches!(self.data.get(self.pos), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        let text = std::str::from_utf8(&self.data[start..self.pos])
            .map_err(|_| "invalid number".to_string())?;
        let value: f64 = text.parse().map_err(|_| "invalid number".to_string())?;
        if !value.is_finite() {
            return Err("number out of range".into());
        }
        Ok(Json::Num(value))
    }

    fn array(&mut self) -> Result<Json, String> {
        self.expect(b'[')?;
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("JSON nesting too deep".into());
        }
        let mut out = Vec::new();
        self.ws();
        if self.data.get(self.pos) == Some(&b']') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Json::Arr(out));
        }
        loop {
            out.push(self.value()?);
            self.ws();
            match self.bump()? {
                b',' => self.ws(),
                b']' => break,
                _ => return Err("expected ',' or ']'".into()),
            }
        }
        self.depth -= 1;
        Ok(Json::Arr(out))
    }

    fn object(&mut self) -> Result<Json, String> {
        self.expect(b'{')?;
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err("JSON nesting too deep".into());
        }
        let mut out: Vec<(String, Json)> = Vec::new();
        self.ws();
        if self.data.get(self.pos) == Some(&b'}') {
            self.pos += 1;
            self.depth -= 1;
            return Ok(Json::Obj(out));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            self.expect(b':')?;
            let value = self.value()?;
            out.push((key, value));
            self.ws();
            match self.bump()? {
                b',' => self.ws(),
                b'}' => break,
                _ => return Err("expected ',' or '}'".into()),
            }
        }
        self.depth -= 1;
        Ok(Json::Obj(out))
    }
}

fn utf8_len(first: u8) -> Option<usize> {
    match first {
        0x00..=0x7f => Some(1),
        0xc2..=0xdf => Some(2),
        0xe0..=0xef => Some(3),
        0xf0..=0xf4 => Some(4),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let raw = r#"{"a":[1,2.5,true,null,"x\n\"y"],"b":{"c":"héllo"}}"#;
        let value = parse(raw.as_bytes()).unwrap();
        assert_eq!(value.get("a").unwrap().as_arr().unwrap().len(), 5);
        assert_eq!(
            value.get("b").unwrap().get("c").unwrap().as_str(),
            Some("héllo")
        );
        let text = value.compact();
        assert_eq!(parse(text.as_bytes()).unwrap(), value);
    }

    #[test]
    fn rejects_bad_input() {
        assert!(parse(b"{\"a\":}").is_err());
        assert!(parse(b"[1,]").is_err());
        assert!(parse(b"\"\\q\"").is_err());
        assert!(parse(b"123 trailing").is_err());
        assert!(parse(b"1e999").is_err());
    }

    #[test]
    fn deep_nesting_is_bounded() {
        let deep = "[".repeat(100) + &"]".repeat(100);
        assert!(parse(deep.as_bytes()).is_err());
    }
}
