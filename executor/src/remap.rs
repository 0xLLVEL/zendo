//! Rewrites compiler stock opcodes to the client's file opcodes.
//!
//!     file = FILE_TO_RUNTIME[CLASS_TO_RUNTIME[stock]]
//!
//! Both tables come from the decrypted image (see tables.rs). Only the low
//! byte of each instruction's first word changes; AUX words are untouched.

use crate::lbc;
use crate::tables::{BIG, CLASS_TO_RUNTIME, FILE_TO_RUNTIME};

pub struct Remapped {
    pub blob: Vec<u8>,
    pub protos: usize,
    pub words: usize,
}

fn has_big(op: u8) -> bool {
    BIG.binary_search(&op).is_ok()
}

fn runtime_to_file() -> [u8; 256] {
    let mut inv = [0u8; 256];
    for (file, &rt) in FILE_TO_RUNTIME.iter().enumerate() {
        inv[rt as usize] = file as u8;
    }
    inv
}

pub fn remap(blob: &[u8]) -> Result<Remapped, String> {
    let bundle = lbc::parse(blob).map_err(|e| e.to_string())?;
    let inv = runtime_to_file();
    let mut out = blob.to_vec();
    let mut changed = 0usize;

    for pr in &bundle.protos {
        let mut i = 0usize;
        while i < pr.sizecode {
            let off = pr.code_off + 4 * i;
            let w = u32::from_le_bytes([
                out[off],
                out[off + 1],
                out[off + 2],
                out[off + 3],
            ]);
            let stock = (w & 0xff) as u8;
            let rt = CLASS_TO_RUNTIME[stock as usize] as usize;
            out[off] = inv[rt];
            changed += 1;
            i += if has_big(stock) { 2 } else { 1 };
        }
        if i != pr.sizecode {
            return Err(format!(
                "loader walk overran proto {}: {} vs {}",
                pr.index, i, pr.sizecode
            ));
        }
    }

    Ok(Remapped {
        blob: out,
        protos: bundle.protos.len(),
        words: changed,
    })
}

/// Prefix the 8-byte load container magic (0xE009325B4A107A52 LE).
pub const MAGIC: [u8; 8] = [0x52, 0x7a, 0x10, 0x4a, 0x5b, 0x32, 0x09, 0xe0];
