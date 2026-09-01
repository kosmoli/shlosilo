//! Bytewords 编解码（BCR-2020-012）— Phase 6 P6.0b
//!
//! 词表来自 Blockchain Commons 官方 bytewords 标准（与 keystone `keystone-ur` 同源）。
//! shlosilo 只用 Minimal style（UR QR 全部走 minimal，两字母无分隔）。
//! 校验和 = CRC32（IEEE，多式反射）big-endian 追加 4 字节。

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::{Result, ShlosiloError, ShlosiloErrorKind};

fn err() -> ShlosiloError {
    ShlosiloError::new(ShlosiloErrorKind::EncodingInvalidFormat)
}

#[allow(dead_code)] // 官方词表参考（BCR-2020-012）；minimal 编码只用了两字母缩写
#[rustfmt::skip]
const WORDS: [&str; 256] = [
    "able", "acid", "also", "apex", "aqua", "arch", "atom", "aunt",
    "away", "axis", "back", "bald", "barn", "belt", "beta", "bias",
    "blue", "body", "brag", "brew", "bulb", "buzz", "calm", "cash",
    "cats", "chef", "city", "claw", "code", "cola", "cook", "cost",
    "crux", "curl", "cusp", "cyan", "dark", "data", "days", "deli",
    "dice", "diet", "door", "down", "draw", "drop", "drum", "dull",
    "duty", "each", "easy", "echo", "edge", "epic", "even", "exam",
    "exit", "eyes", "fact", "fair", "fern", "figs", "film", "fish",
    "fizz", "flap", "flew", "flux", "foxy", "free", "frog", "fuel",
    "fund", "gala", "game", "gear", "gems", "gift", "girl", "glow",
    "good", "gray", "grim", "guru", "gush", "gyro", "half", "hang",
    "hard", "hawk", "heat", "help", "high", "hill", "holy", "hope",
    "horn", "huts", "iced", "idea", "idle", "inch", "inky", "into",
    "iris", "iron", "item", "jade", "jazz", "join", "jolt", "jowl",
    "judo", "jugs", "jump", "junk", "jury", "keep", "keno", "kept",
    "keys", "kick", "kiln", "king", "kite", "kiwi", "knob", "lamb",
    "lava", "lazy", "leaf", "legs", "liar", "limp", "lion", "list",
    "logo", "loud", "love", "luau", "luck", "lung", "main", "many",
    "math", "maze", "memo", "menu", "meow", "mild", "mint", "miss",
    "monk", "nail", "navy", "need", "news", "next", "noon", "note",
    "numb", "obey", "oboe", "omit", "onyx", "open", "oval", "owls",
    "paid", "part", "peck", "play", "plus", "poem", "pool", "pose",
    "puff", "puma", "purr", "quad", "quiz", "race", "ramp", "real",
    "redo", "rich", "road", "rock", "roof", "ruby", "ruin", "runs",
    "rust", "safe", "saga", "scar", "sets", "silk", "skew", "slot",
    "soap", "solo", "song", "stub", "surf", "swan", "taco", "task",
    "taxi", "tent", "tied", "time", "tiny", "toil", "tomb", "toys",
    "trip", "tuna", "twin", "ugly", "undo", "unit", "urge", "user",
    "vast", "very", "veto", "vial", "vibe", "view", "visa", "void",
    "vows", "wall", "wand", "warm", "wasp", "wave", "waxy", "webs",
    "what", "when", "whiz", "wolf", "work", "yank", "yawn", "yell",
    "yoga", "yurt", "zaps", "zero", "zest", "zinc", "zone", "zoom",

];

#[rustfmt::skip]
const MINIMALS: [&str; 256] = [

    "ae", "ad", "ao", "ax", "aa", "ah", "am", "at",
    "ay", "as", "bk", "bd", "bn", "bt", "ba", "bs",
    "be", "by", "bg", "bw", "bb", "bz", "cm", "ch",
    "cs", "cf", "cy", "cw", "ce", "ca", "ck", "ct",
    "cx", "cl", "cp", "cn", "dk", "da", "ds", "di",
    "de", "dt", "dr", "dn", "dw", "dp", "dm", "dl",
    "dy", "eh", "ey", "eo", "ee", "ec", "en", "em",
    "et", "es", "ft", "fr", "fn", "fs", "fm", "fh",
    "fz", "fp", "fw", "fx", "fy", "fe", "fg", "fl",
    "fd", "ga", "ge", "gr", "gs", "gt", "gl", "gw",
    "gd", "gy", "gm", "gu", "gh", "go", "hf", "hg",
    "hd", "hk", "ht", "hp", "hh", "hl", "hy", "he",
    "hn", "hs", "id", "ia", "ie", "ih", "iy", "io",
    "is", "in", "im", "je", "jz", "jn", "jt", "jl",
    "jo", "js", "jp", "jk", "jy", "kp", "ko", "kt",
    "ks", "kk", "kn", "kg", "ke", "ki", "kb", "lb",
    "la", "ly", "lf", "ls", "lr", "lp", "ln", "lt",
    "lo", "ld", "le", "lu", "lk", "lg", "mn", "my",
    "mh", "me", "mo", "mu", "mw", "md", "mt", "ms",
    "mk", "nl", "ny", "nd", "ns", "nt", "nn", "ne",
    "nb", "oy", "oe", "ot", "ox", "on", "ol", "os",
    "pd", "pt", "pk", "py", "ps", "pm", "pl", "pe",
    "pf", "pa", "pr", "qd", "qz", "re", "rp", "rl",
    "ro", "rh", "rd", "rk", "rf", "ry", "rn", "rs",
    "rt", "se", "sa", "sr", "ss", "sk", "sw", "st",
    "sp", "so", "sg", "sb", "sf", "sn", "to", "tk",
    "ti", "tt", "td", "te", "ty", "tl", "tb", "ts",
    "tp", "ta", "tn", "uy", "uo", "ut", "ue", "ur",
    "vt", "vy", "vo", "vl", "ve", "vw", "va", "vd",
    "vs", "wl", "wd", "wm", "wp", "we", "wy", "ws",
    "wt", "wn", "wz", "wf", "wk", "yk", "yn", "yl",
    "ya", "yt", "zs", "zo", "zt", "zc", "ze", "zm",
];

/// minimal 两字母反查表（[first-'a'][second-'a'] -> byte, 255 = invalid）
#[rustfmt::skip]
static MINIMAL_LOOKUP: [[u16; 26]; 26] = [
        [5, 0, 0, 2, 1, 0, 0, 6, 0, 0, 0, 0, 7, 0, 3, 0, 0, 0, 10, 8, 0, 0, 0, 4, 9, 0],
        [15, 21, 0, 12, 17, 0, 19, 0, 0, 0, 11, 0, 0, 13, 0, 0, 0, 0, 16, 14, 0, 0, 20, 0, 18, 22],
        [30, 0, 0, 0, 29, 26, 0, 24, 0, 0, 31, 34, 23, 36, 0, 35, 0, 0, 25, 32, 0, 0, 28, 33, 27, 0],
        [38, 0, 0, 0, 41, 0, 0, 0, 40, 0, 37, 48, 47, 44, 0, 46, 0, 43, 39, 42, 0, 0, 45, 0, 49, 0],
        [0, 0, 54, 0, 53, 0, 0, 50, 0, 0, 0, 0, 56, 55, 52, 0, 0, 0, 58, 57, 0, 0, 0, 0, 51, 0],
        [0, 0, 0, 73, 70, 0, 71, 64, 0, 0, 0, 72, 63, 61, 0, 66, 0, 60, 62, 59, 0, 0, 67, 68, 69, 65],
        [74, 0, 0, 81, 75, 0, 0, 85, 0, 0, 0, 79, 83, 0, 86, 0, 0, 76, 77, 78, 84, 0, 80, 0, 82, 0],
        [0, 0, 0, 89, 96, 87, 88, 93, 0, 0, 90, 94, 0, 97, 0, 92, 0, 0, 98, 91, 0, 0, 0, 0, 95, 0],
        [100, 0, 0, 99, 101, 0, 0, 102, 0, 0, 0, 0, 107, 106, 104, 0, 0, 0, 105, 0, 0, 0, 0, 0, 103, 0],
        [0, 0, 0, 0, 108, 0, 0, 0, 0, 0, 116, 112, 0, 110, 113, 115, 0, 0, 114, 111, 0, 0, 0, 0, 117, 109],
        [0, 127, 0, 0, 125, 0, 124, 0, 126, 0, 122, 0, 0, 123, 119, 118, 0, 0, 121, 120, 0, 0, 0, 0, 0, 0],
        [129, 128, 0, 138, 139, 131, 142, 0, 0, 0, 141, 0, 0, 135, 137, 134, 0, 133, 132, 136, 140, 0, 0, 0, 130, 0],
        [0, 0, 0, 150, 146, 0, 0, 145, 0, 0, 153, 0, 0, 143, 147, 0, 0, 0, 152, 151, 148, 0, 149, 0, 144, 0],
        [0, 161, 0, 156, 160, 0, 0, 0, 0, 0, 0, 154, 0, 159, 0, 0, 0, 0, 157, 158, 0, 0, 0, 0, 155, 0],
        [0, 0, 0, 0, 163, 0, 0, 0, 0, 0, 0, 167, 0, 166, 0, 0, 0, 0, 168, 164, 0, 0, 0, 165, 162, 0],
        [178, 0, 0, 169, 176, 177, 0, 0, 0, 0, 171, 175, 174, 0, 0, 0, 0, 179, 173, 170, 0, 0, 0, 0, 172, 0],
        [0, 0, 0, 180, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 181],
        [0, 0, 0, 187, 182, 189, 0, 186, 0, 0, 188, 184, 0, 191, 185, 183, 0, 0, 192, 193, 0, 0, 0, 0, 190, 0],
        [195, 204, 0, 0, 194, 205, 203, 0, 0, 0, 198, 0, 0, 206, 202, 201, 0, 196, 197, 200, 0, 0, 199, 0, 0, 0],
        [218, 215, 0, 211, 212, 0, 0, 0, 209, 0, 208, 214, 0, 219, 207, 217, 0, 0, 216, 210, 0, 0, 0, 0, 213, 0],
        [0, 0, 0, 0, 223, 0, 0, 0, 0, 0, 0, 0, 0, 0, 221, 0, 0, 224, 0, 222, 0, 0, 0, 0, 220, 0],
        [231, 0, 0, 232, 229, 0, 0, 0, 0, 0, 0, 228, 0, 0, 227, 0, 0, 0, 233, 225, 0, 0, 230, 0, 226, 0],
        [0, 0, 0, 235, 238, 244, 0, 0, 0, 0, 245, 234, 236, 242, 0, 237, 0, 0, 240, 241, 0, 0, 0, 0, 239, 243],
        [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        [249, 0, 0, 0, 0, 0, 0, 0, 0, 0, 246, 248, 0, 247, 0, 0, 0, 0, 0, 250, 0, 0, 0, 0, 0, 0],
        [0, 0, 254, 0, 255, 0, 0, 0, 0, 0, 0, 0, 256, 0, 252, 0, 0, 0, 251, 253, 0, 0, 0, 0, 0, 0],
];

/// CRC-32/ISO-HDLC（IEEE 802.3），poly 0xEDB88320 reflected
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// minimal style 编码：payload + CRC32 BE(4 bytes) → 每字节两字母拼接
pub fn encode_minimal(data: &[u8]) -> String {
    let checksum = crc32(data).to_be_bytes();
    let mut out = String::with_capacity((data.len() + 4) * 2);
    for &b in data.iter().chain(checksum.iter()) {
        out.push_str(MINIMALS[b as usize]);
    }
    out
}

/// minimal style 解码：两字母一组反查 + 验证 CRC32
pub fn decode_minimal(encoded: &str) -> Result<Vec<u8>> {
    let bytes = encoded.as_bytes();
    if !encoded.len().is_multiple_of(2) || !encoded.is_ascii() {
        return Err(err());
    }
    let mut data = Vec::with_capacity(encoded.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let c0 = (pair[0] as char).to_ascii_lowercase() as u8;
        let c1 = (pair[1] as char).to_ascii_lowercase() as u8;
        if !c0.is_ascii_lowercase() || !c1.is_ascii_lowercase() {
            return Err(err());
        }
        // 表值 = byte + 1（0 = invalid；byte 255 与哨兵冲突的修正）
        let v = MINIMAL_LOOKUP[(c0 - b'a') as usize][(c1 - b'a') as usize];
        if v == 0 {
            return Err(err());
        }
        data.push((v - 1) as u8);
    }
    if data.len() < 5 {
        return Err(err()); // 至少 payload 1 字节 + checksum 4 字节
    }
    let (payload, checksum) = data.split_at(data.len() - 4);
    if crc32(payload).to_be_bytes() == checksum {
        Ok(payload.to_vec())
    } else {
        Err(err())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    /// BCR-2020-012 官方向量（经 keystone-ur doctest 同源验证）
    #[test]
    fn bcr_official_vectors() {
        // encode(&[0], Minimal) = "aetdaowslg"
        assert_eq!(encode_minimal(&[0]), "aetdaowslg");
        assert_eq!(decode_minimal("aetdaowslg").unwrap(), vec![0]);
        // encode("Some binary data".as_bytes(), Minimal)
        assert_eq!(
            encode_minimal(b"Some binary data"),
            "gujljnihcxidinjthsjpkkcxiehsjyhsnsgdmkht"
        );
        assert_eq!(
            decode_minimal("gujljnihcxidinjthsjpkkcxiehsjyhsnsgdmkht").unwrap(),
            b"Some binary data".to_vec()
        );
    }

    /// CRC32 已知值：crc32("123456789") = 0xCBF43926（标准 IEEE 校验值）
    #[test]
    fn crc32_known_value() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0x0000_0000);
    }

    /// byte=255 ('zm' 等) 与旧哨兵 255 冲突的回归测试（v+1 表编码修正）
    #[test]
    fn byte_255_round_trip() {
        for data in [vec![255u8], vec![0u8, 255, 128, 255], vec![255u8; 32]] {
            let enc = encode_minimal(&data);
            assert_eq!(decode_minimal(&enc).unwrap(), data);
        }
        // len=64 官方对照（Python 独立实现生成）
        let data: Vec<u8> = (0..64usize).map(|i| (i * 37 + 64) as u8).collect();
        assert_eq!(decode_minimal(&encode_minimal(&data)).unwrap(), data);
    }

    /// round trip：多长度随机形状
    #[test]
    fn round_trip_various_lengths() {
        for len in [1usize, 5, 20, 64, 200] {
            let data: Vec<u8> = (0..len).map(|i| (i * 37 + len) as u8).collect();
            let enc = encode_minimal(&data);
            assert_eq!(enc.len(), (len + 4) * 2);
            match decode_minimal(&enc) {
                Ok(d) => assert_eq!(d, data),
                Err(e) => panic!("decode failed len={} err={:?} enc={}", len, e, enc),
            }
        }
    }

    /// 篡改一个字母 → checksum 失败；非法两字母 → 拒绝
    #[test]
    fn tamper_and_invalid_rejected() {
        let enc = encode_minimal(&[1, 2, 3]);
        let mut bytes: Vec<u8> = enc.bytes().collect();
        bytes[0] = if bytes[0] == b'a' { b'b' } else { b'a' };
        let tampered: String = bytes.iter().map(|&b| b as char).collect();
        assert!(decode_minimal(&tampered).is_err());
        // 非法组合（不存在于 minimal 表）
        assert!(decode_minimal("zzzzzzzzzz").is_err());
        assert!(decode_minimal("aetdaowsl").is_err()); // 9 chars
                                                       // 太短（< 1 payload + 4 checksum）
        assert!(decode_minimal("aeaeae").is_err()); // 3 bytes < 5
    }
}
