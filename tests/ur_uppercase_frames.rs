//! BC-UR 大小写不敏感（真实 Sparrow 帧回归钉）
//!
//! Sparrow 的签名 QR 用的是 QR **alphanumeric** 模式（该模式没有小写字母），
//! 所以整个 UR 串被编码成大写：`UR:CRYPTO-PSBT/119-2/LPCSKT…`。
//! BC-UR 规定解码方向大小写不敏感（编码器可以全大写，解码器必须认）。
//!
//! 我方从 Cake/Feather 收到的全是小写（byte 模式），所以这个面从未被覆盖——
//! 2026-11-04 真机首测 Sparrow 时，设备把 `CRYPTO-PSBT` 当成未知类型，屏上打
//! `collected: unknown code, not a sign request`。
//!
//! 本文件的帧是从用户拍的 Sparrow 动画里 zbar 逐帧解出来的**真字节**。

use shlosilo::ur::ur_encode::UrTypeTag;
use shlosilo::ur::ur_multipart::UrMultipartDecoder;

/// Sparrow 动画里连续解出的四个 fountain 帧（seq-count = 119-2 / 121-2 /
/// 124-2 / 126-2，即 2 个原始分片 + 冗余混合帧）
const SPARROW_UPPER_FRAMES: &[&str] = &[
    "UR:CRYPTO-PSBT/119-2/LPCSKTAOCFADRNCYFPVYFZLGHDURHDCKSPNLKNIDJYZMADAEIOAOBBEYMTGDPFSEAMSTKNDRCMQZHFENMWLOZMLURNSNRDLNGOYNHPVDGHGLSSDNKOPAATRNOXTPGOFHVLVATPPYHPSNOYRLBSHFKTPKWYBKNTECIASSLNKGPSOSDPFRTAHSURAESTMDKKGWCALTLDRYLAJPTKESVDLDAEAEAEAEAXCMAEBBNNQDCEGOATJNEYFZBARSAMZTBGWENNLBWPENUTIMGSHLFEFMUYFWBDWLPFWSPLCLPKZSSEDNCSWFRHAEHNWSTKGTONDEYNFZCSAMWLFNOTASHSRELUTSDSTAJYBKPSVAJLCLWLQZPMDRUTMWCWGSPMJZBWGORYESTKDIBGHGFPBAMWTPNSBEPAVSWERTRTLSADCYSNUEMOROGYRKBEJKROMTBDTYAEAELALYADAELAAEADAELAAEADIATKJOBS",
    "UR:CRYPTO-PSBT/121-2/LPCSKKAOCFADRNCYFPVYFZLGHDURADCTJKWLASAEAEAEAEAECMAEBBEYMTGYAYHEDSVYJNBNSRMDRLHHCLVSGDTLIHEOCPADAXAAADAEAEAECPAMAOSNHTNSSNGWGOFHVLVATPHFOXEYHYREZOHGKTPKWYBKNTECKPSSMOOYFZSAECLKYNCSWFRHMTBDGHAEAELAADAEAELAAEAEAELAAEAEAEAEAXAEAEAEAECPAOAOAMNTMODKOSVDJTHYLYGEZCDSKEPSFGYNDLHPFZFMMWFXBSUOEMCXPMSNBDIYBBPYCSWFRHMTBDGHAEAELAADAEAELAAEAEAELAAEAEAEAEAAAEAEAEAECPAOAOPEGLDWNNATVLMSSTHEWZVEKNAMCMTIKEJTAEFRKKLRVOBNLYNDNTCKDITDTKTIFDCSWFRHMTBDGHAEAELAADAEAELAAEAEAELAADAEAEAEADAEAEAEAEWPNNADST",
    "UR:CRYPTO-PSBT/124-2/LPCSKEAOCFADRNCYFPVYFZLGHDURHKADRKJOJKIDJYZMADAEJSAOAEAEAEADRONNCXDSCHDSTLCLVYIMREHNPEHYUYZEMKLTHFWZHTVDGHGLVADPJYKEHLCPINMSAEAEAEAEAEZCZMZMZMAOWKADAEAEAEAEAEAECMAEBBTNWPIHCSRLDLKKDWRHGYNNDPGWCAATLORYLAWZTKESVDASAEAEAEAEAECMAEBBNNMECKHGADWTNBIEPTHDISOEMUOSIAHKMHNYNDNSIAAMAHAEGWADAAECLTTKAXWPOYNSTLLAAEAEAEMTJERKTKGTDADTYNFZMKAMWLFNCNASHSRELUTEDSTAJYBKMNVEJNMNOSMKEODPFMAXUOBWHELOINGUPYWLQDGABGJZETLEKOTYCALUDWYNSGBGBSGUGAAOFMIOAAQDAHRKBEWFRHMTBDGHAEAELAADAEAELAAEAEAELAAEADWNIABWWF",
    "UR:CRYPTO-PSBT/126-2/LPCSKBAOCFADRNCYFPVYFZLGHDURHDCKSPNLKNIDJYZMADAEIOAOBBEYMTGDPFSEAMSTKNDRCMQZHFENMWLOZMLURNSNRDLNGOYNHPVDGHGLSSDNKOPAATRNOXTPGOFHVLVATPPYHPSNOYRLBSHFKTPKWYBKNTECIASSLNKGPSOSDPFRTAHSURAESTMDKKGWCALTLDRYLAJPTKESVDLDAEAEAEAEAXCMAEBBNNQDCEGOATJNEYFZBARSAMZTBGWENNLBWPENUTIMGSHLFEFMUYFWBDWLPFWSPLCLPKZSSEDNCSWFRHAEHNWSTKGTONDEYNFZCSAMWLFNOTASHSRELUTSDSTAJYBKPSVAJLCLWLQZPMDRUTMWCWGSPMJZBWGORYESTKDIBGHGFPBAMWTPNSBEPAVSWERTRTLSADCYSNUEMOROGYRKBEJKROMTBDTYAEAELALYADAELAAEADAELAAEADKSZSWEYT",
];

const SCRATCH: usize = 4096;

/// 类型名匹配必须大小写不敏感
#[test]
fn type_tag_lookup_is_case_insensitive() {
    assert_eq!(UrTypeTag::from_name("CRYPTO-PSBT"), UrTypeTag::CryptoPsbt);
    assert_eq!(
        UrTypeTag::from_name("ETH-SIGN-REQUEST"),
        UrTypeTag::EthSignRequest
    );
    assert_eq!(UrTypeTag::from_name("Crypto-Psbt"), UrTypeTag::CryptoPsbt);
}

/// 真实 Sparrow 帧：解码器必须接受大写帧头，并把类型规范化成小写交给上层
///
/// 便利构造 `UrMultipartDecoder::new()` 只在 alloc 面存在（它内部 leak 一套
/// 自己的 workspace）；设备面走的是调用方 workspace 那条路，由下面的
/// `device_ffi_path_…` 覆盖——两个面都要有钉，但钉子不能跨面编译。
#[cfg(feature = "alloc-fallback")]
#[test]
fn sparrow_uppercase_frames_decode_to_crypto_psbt() {
    let mut dec = UrMultipartDecoder::new();
    let mut scratch = [0u8; SCRATCH];
    let mut accepted = 0usize;
    for f in SPARROW_UPPER_FRAMES {
        match dec.receive_frame_with(f, &mut scratch) {
            Ok(_) => accepted += 1,
            Err(e) => panic!("frame rejected: {e:?}\n  {f}"),
        }
    }
    assert!(accepted > 0, "至少一帧必须被接收");
    // 类型串必须是规范化后的小写（C 侧按小写名做分派）
    assert_eq!(dec.ur_type(), Some("crypto-psbt"), "type normalization");

    // 端到端：四个 fountain 帧必须把整条消息重建出来，且载荷是一份 PSBT
    assert!(dec.complete(), "四个 fountain 帧应足以重建两条分片的消息");
    let mut out = [0u8; 8192];
    let n = dec
        .payload_into(&mut out)
        .expect("payload_into")
        .expect("complete payload");
    assert!(n > 100, "PSBT 载荷长度异常: {n}");
    assert_eq!(&out[..5], b"psbt\xff", "载荷不是 PSBT（魔数不符）");
}

/// 设备同款路径（C 侧真正调的那串 FFI + 调用方 workspace）：
/// 把视频里解出的全部帧逐条喂进去，任何一帧被拒都必须报出返回码。
/// 这条钉存在的理由：2026-11-04 真机报 `scan failed / code not recognized`，
/// 而同一批帧走 `UrMultipartDecoder::new()` 的测试路径是绿的——测试路径与
/// 设备路径（caller-workspace carve）不是同一条，必须分开钉。
#[test]
fn device_ffi_path_accepts_every_sparrow_frame() {
    use core::ffi::c_uint;
    use shlosilo::ffi::c_abi;
    use std::ffi::CString;

    let all = include_str!("../tests/fixtures/sparrow_frames.txt");
    let frames: Vec<&str> = all.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(frames.len() >= 20, "夹具帧数异常: {}", frames.len());

    let ws_need = shlosilo::ur::ur_multipart::ur_decode_ws_len();
    let mut ws = vec![0u8; ws_need];
    let dec = c_abi::r3::shlosilo_ur_decode_new(ws.as_mut_ptr(), ws_need as c_uint);
    assert!(!dec.is_null(), "decoder init failed");

    let mut accepted_total = 0u32;
    for (i, f) in frames.iter().enumerate() {
        let c = CString::new(*f).unwrap();
        let mut accepted: c_uint = 0;
        let rc = c_abi::r3::shlosilo_ur_decode_feed(dec, c.as_ptr(), &mut accepted);
        assert_eq!(
            rc,
            0,
            "帧 #{} 被拒 rc={} len={} seq段={}",
            i,
            rc,
            f.len(),
            f.split('/').nth(1).unwrap_or("?")
        );
        accepted_total += accepted;
    }
    assert!(accepted_total > 0, "没有任何一帧带来新信息");
    assert_eq!(
        c_abi::r3::shlosilo_ur_decode_complete(dec),
        1,
        "帧齐了仍未 complete"
    );

    let mut tlen: c_uint = 0;
    let mut ty = [0u8; 32];
    assert_eq!(
        c_abi::r3::shlosilo_ur_decode_type(dec, ty.as_mut_ptr(), ty.len() as c_uint, &mut tlen),
        0
    );
    let t = core::str::from_utf8(&ty[..(tlen as usize).saturating_sub(1)]).unwrap();
    assert_eq!(t, "crypto-psbt", "类型应为规范化后的小写");

    c_abi::r3::shlosilo_ur_decode_free(dec);
}
