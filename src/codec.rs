// ASM 自定义编码 —— 复刻 ASMBase64StringFromText / GBK 解码
use base64::Engine;

/// 自定义 Base64: 标准 Base64 后 = → : , + → , , / → .
pub fn asm_base64(data: &[u8]) -> String {
    let s = base64::engine::general_purpose::STANDARD.encode(data);
    s.replace('=', ":").replace('+', ",").replace('/', ".")
}

/// 反向: asm_base64 → 原始字节 (用于调试/自测)
#[allow(dead_code)]
pub fn asm_base64_decode(s: &str) -> Vec<u8> {
    let std = s
        .replace(':', "=")
        .replace(',', "+")
        .replace('.', "/");
    base64::engine::general_purpose::STANDARD
        .decode(std)
        .unwrap_or_default()
}

/// GB2312(GBK) 编码后自定义 Base64 —— username / authserver / dev_xml 用
pub fn encode_gbk(s: &str) -> String {
    let (gb, _, _) = encoding_rs::GBK.encode(s);
    asm_base64(&gb)
}

/// ASCII 编码后自定义 Base64 —— password 用 (ASM 用 NSASCIIStringEncoding)
pub fn encode_ascii(s: &str) -> String {
    asm_base64(s.as_bytes())
}

/// 服务端响应常把 GBK 字节当 Latin-1 再编 UTF-8 —— 逆向还原
pub fn fix_gbk_mojibake(s: &str) -> String {
    if !s.chars().any(|c| (c as u32) > 0x7F && (c as u32) <= 0xFF) {
        return s.to_string();
    }
    let bytes: Vec<u8> = s
        .chars()
        .map(|c| {
            let cp = c as u32;
            if cp <= 0xFF {
                cp as u8
            } else {
                // 无法映射的字符直接丢弃高位（ASM 场景不会出现）
                cp as u8
            }
        })
        .collect();
    let (decoded, _, _) = encoding_rs::GBK.decode(&bytes);
    decoded.into_owned()
}

pub fn fix_json_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => *s = fix_gbk_mojibake(s),
        serde_json::Value::Array(a) => a.iter_mut().for_each(fix_json_value),
        serde_json::Value::Object(o) => o.iter_mut().for_each(|(_, x)| fix_json_value(x)),
        _ => {}
    }
}

/// local_lguage_set: zh / en
pub fn lang() -> &'static str {
    std::env::var("LANG")
        .ok()
        .filter(|l| l.starts_with("zh"))
        .map(|_| "zh")
        .unwrap_or("en")
}

/// 解码 plist 文本输出里的 `\UXXXX` / `\uXXXX` 转义。
///
/// `defaults read com.infogo.MAC3 checkres` 把 XML 里的中文全转成这种转义
/// （`\u7981` = 禁），直接拿去 POST 等于发了一串字面量反斜杠，服务器不认。
pub fn decode_unicode_escapes(s: &str) -> String {
    let cs: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    while i < cs.len() {
        if cs[i] == '\\'
            && i + 5 < cs.len()
            && (cs[i + 1] == 'U' || cs[i + 1] == 'u')
            && cs[i + 2..i + 6].iter().all(|c| c.is_ascii_hexdigit())
        {
            let hex: String = cs[i + 2..i + 6].iter().collect();
            if let Ok(cp) = u32::from_str_radix(&hex, 16) {
                if let Some(c) = char::from_u32(cp) {
                    out.push(c);
                    i += 6;
                    continue;
                }
            }
        }
        out.push(cs[i]);
        i += 1;
    }
    out
}

/// 按 GBK 编码后转 percent-encoding (`%xx`)，用于 checkres 这类原始 XML 字段。
///
/// ASM 的 XML 声明是 `encoding="gbk"`，必须发 GBK 字节；而 `.query()` 只会编 UTF-8。
pub fn gbk_percent_encode(s: &str) -> String {
    let (gb, _, _) = encoding_rs::GBK.encode(s);
    let mut out = String::with_capacity(gb.len() * 3);
    for b in gb.iter() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// ASCII/UTF-8 的 percent-encoding（query 里那些普通字段用）
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match *b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asm_b64_mapping() {
        // "a?" GBK 0x613F -> "YT8=" -> "YT8:"
        assert_eq!(encode_ascii("a?"), "YT8:");
        // + -> , ; / -> .
        assert_eq!(asm_base64(&[0xfb, 0xff]), ",.8:");
        assert_eq!(asm_base64_decode(&encode_ascii("abc123")), b"abc123");
    }
}
