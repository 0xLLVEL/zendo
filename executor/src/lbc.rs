//! LBC v14 parser: walks the serialized proto tree and reports each proto's
//! instruction span so the remapper can rewrite opcode bytes in place.
//!
//! Layout (see BytecodeBuilder::writeFunction):
//!   5 x u8 header, typeinfo blob, code, constants, children, linedefined,
//!   debugname, line info, debug info, feedback slots, optional inline cost.

pub const LPF_INLINABLE: u8 = 0x08;
const LFT_CALLTARGET: u8 = 0;
const LFT_CONSTRUCT: u8 = 1;

#[derive(Debug)]
pub struct LbcError(pub String);

impl std::fmt::Display for LbcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LbcError {}

type Result<T> = std::result::Result<T, LbcError>;

fn err<T>(msg: impl Into<String>) -> Result<T> {
    Err(LbcError(msg.into()))
}

#[derive(Clone, Debug)]
pub struct Proto {
    pub index: usize,
    pub blob_off: usize,
    pub blob_size: usize,
    pub maxstack: u8,
    pub numparams: u8,
    pub nups: u8,
    pub isvararg: u8,
    pub flags: u8,
    pub code_off: usize,
    pub sizecode: usize,
    pub children: Vec<usize>,
    pub linedefined: usize,
    pub debugname: usize,
    pub has_lines: u8,
    pub has_debug: u8,
    pub fb_slots: usize,
    pub cost: Option<usize>,
}

fn rv(b: &[u8], p: &mut usize) -> Result<usize> {
    let mut x: u64 = 0;
    let mut sh = 0;
    loop {
        let c = *b
            .get(*p)
            .ok_or_else(|| LbcError(format!("varint past EOF at 0x{:x}", *p)))?;
        *p += 1;
        x |= ((c & 0x7f) as u64) << sh;
        if c & 0x80 == 0 {
            return Ok(x as usize);
        }
        sh += 7;
        if sh > 63 {
            return err(format!("varint overflow at 0x{:x}", *p));
        }
    }
}

fn skip_constants(b: &[u8], p: &mut usize, n: usize) -> Result<()> {
    for i in 0..n {
        let t = *b
            .get(*p)
            .ok_or_else(|| LbcError(format!("constant {} past EOF", i)))?;
        *p += 1;
        match t {
            0 => {}
            1 => *p += 1,
            2 => *p += 8,
            3 => {
                rv(b, p)?;
            }
            4 => *p += 4,
            5 => {
                let cn = rv(b, p)?;
                for _ in 0..cn {
                    rv(b, p)?;
                }
            }
            6 => {
                rv(b, p)?;
            }
            7 => *p += 16,
            8 => {
                let cn = rv(b, p)?;
                for _ in 0..cn {
                    rv(b, p)?;
                    *p += 4;
                }
            }
            9 => {
                *p += 1;
                rv(b, p)?;
            }
            10 => {
                rv(b, p)?;
                *p += 2;
                let np = rv(b, p)?;
                rv(b, p)?;
                let nm = rv(b, p)?;
                rv(b, p)?;
                for _ in 0..np {
                    rv(b, p)?;
                }
                for _ in 0..nm {
                    rv(b, p)?;
                }
            }
            11 => *p += 32,
            other => {
                return err(format!(
                    "constant tag {} at 0x{:x}",
                    other,
                    *p - 1
                ))
            }
        }
        if *p > b.len() {
            return err(format!("constant {} past EOF", i));
        }
    }
    Ok(())
}

fn parse_function(b: &[u8], p: &mut usize, size: usize, index: usize) -> Result<Proto> {
    let end = *p + size;
    if size < 6 {
        return err(format!("proto {} blob too small ({})", index, size));
    }
    if end > b.len() {
        return err(format!("proto {} blob past EOF", index));
    }
    let mut pr = Proto {
        index,
        blob_off: *p,
        blob_size: size,
        maxstack: b[*p],
        numparams: b[*p + 1],
        nups: b[*p + 2],
        isvararg: b[*p + 3],
        flags: b[*p + 4],
        code_off: 0,
        sizecode: 0,
        children: Vec::new(),
        linedefined: 0,
        debugname: 0,
        has_lines: 0,
        has_debug: 0,
        fb_slots: 0,
        cost: None,
    };
    *p += 5;

    let tilen = rv(b, p)?;
    *p += tilen;
    let ncode = rv(b, p)?;
    pr.sizecode = ncode;
    pr.code_off = *p;
    *p += 4 * ncode;
    let nk = rv(b, p)?;
    skip_constants(b, p, nk)?;
    let nch = rv(b, p)?;
    for _ in 0..nch {
        let c = rv(b, p)?;
        pr.children.push(c);
    }
    pr.linedefined = rv(b, p)?;
    pr.debugname = rv(b, p)?;

    pr.has_lines = *b.get(*p).ok_or_else(|| LbcError("eof at has_lines".into()))?;
    *p += 1;
    if pr.has_lines != 0 {
        let logspan = *b.get(*p).ok_or_else(|| LbcError("eof at logspan".into()))? as usize;
        *p += 1;
        *p += ncode;
        let span = 1usize << logspan;
        let baseline = if ncode == 0 { 0 } else { (ncode - 1) / span + 1 };
        *p += 4 * baseline;
    }

    pr.has_debug = *b.get(*p).ok_or_else(|| LbcError("eof at has_debug".into()))?;
    *p += 1;
    if pr.has_debug != 0 {
        let nloc = rv(b, p)?;
        for _ in 0..nloc {
            rv(b, p)?;
            rv(b, p)?;
            rv(b, p)?;
            *p += 1;
        }
        let nup = rv(b, p)?;
        for _ in 0..nup {
            rv(b, p)?;
        }
    }

    pr.fb_slots = rv(b, p)?;
    for _ in 0..pr.fb_slots {
        let kind = *b.get(*p).ok_or_else(|| LbcError("eof at fb kind".into()))?;
        *p += 1;
        if kind == LFT_CALLTARGET || kind == LFT_CONSTRUCT {
            rv(b, p)?;
        }
    }

    if pr.flags & LPF_INLINABLE != 0 {
        pr.cost = Some(rv(b, p)?);
    }

    if *p != end {
        return err(format!(
            "proto {} blob overrun: parsed 0x{:x}, blob ends 0x{:x} (delta {})",
            index,
            *p,
            end,
            *p as isize - end as isize
        ));
    }
    Ok(pr)
}

pub struct Bundle {
    pub version: u8,
    pub types_version: u8,
    pub protos: Vec<Proto>,
    pub main: usize,
}

pub fn parse(b: &[u8]) -> Result<Bundle> {
    if b.len() < 4 {
        return err("too short");
    }
    let version = b[0];
    let types_version = b[1];
    if version != 0x0e {
        return err(format!(
            "version 0x{:02x}, expected 0x0e",
            version
        ));
    }
    let mut p = 2usize;
    let ns = rv(b, &mut p)?;
    for _ in 0..ns {
        let n = rv(b, &mut p)?;
        p += n;
        if p > b.len() {
            return err("string past EOF");
        }
    }
    loop {
        let idx = *b.get(p).ok_or_else(|| LbcError("eof at usertype".into()))?;
        p += 1;
        if idx == 0 {
            break;
        }
        rv(b, &mut p)?;
    }
    let nproto = rv(b, &mut p)?;
    let mut protos = Vec::with_capacity(nproto);
    for i in 0..nproto {
        let size = rv(b, &mut p)?;
        let pr = parse_function(b, &mut p, size, i)?;
        protos.push(pr);
    }
    let main = rv(b, &mut p)?;
    if p != b.len() {
        return err(format!(
            "EOF mismatch: parsed 0x{:x} of 0x{:x}",
            p,
            b.len()
        ));
    }
    Ok(Bundle {
        version,
        types_version,
        protos,
        main,
    })
}
