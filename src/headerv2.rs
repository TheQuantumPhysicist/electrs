//! Support for the 164-byte BLAKE2b block header introduced by Bitcoin Knots.

use anyhow::{anyhow, bail, ensure, Result};
use bitcoin::block::Header as HeaderV1;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{BlockHash, TxMerkleNode};

pub const VERSION_HEADER_V2_FLAG: u32 = 0x8000_0000;
pub const HEADER_V1_SIZE: usize = 80;
pub const HEADER_V2_SIZE: usize = 164;

// Retained as part of HeaderV2 timestamp semantics even though electrs does not
// currently consume the adjusted timestamp in production.
#[allow(dead_code)]
const FLAG_USE_TIME_OFFSET: u8 = 0x04;

pub fn header_size(bytes: &[u8]) -> Result<usize> {
    ensure!(bytes.len() >= 4, "need 4 bytes to read the version field");
    let version = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    Ok(if version & VERSION_HEADER_V2_FLAG != 0 {
        HEADER_V2_SIZE
    } else {
        HEADER_V1_SIZE
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderV2 {
    pub version: u32,
    pub prev_blockhash: BlockHash,
    pub merkle_root: TxMerkleNode,
    pub time_on_wire: u32,
    pub bits: u32,
    pub nonce: u32,
    pub nonce2: u32,
    pub nonce3: u32,
    pub extranonce: [u8; 16],
    pub time_offset: u32,
    pub txcount: u16,
    pub flags: u8,
    pub xor_key_mask_clear_bits: u8,
    pub xor_key: [u8; 16],
    pub height: u32,
    pub mm_rhs: [u8; 32],
}

fn tagged(tag: &str, payload: &[u8]) -> [u8; 32] {
    let t = sha256::Hash::hash(tag.as_bytes());
    let mut buf = Vec::with_capacity(64 + payload.len());
    buf.extend_from_slice(t.as_byte_array());
    buf.extend_from_slice(t.as_byte_array());
    buf.extend_from_slice(payload);
    sha256::Hash::hash(&buf).to_byte_array()
}

fn blake2b256(data: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .hash(data)
        .as_bytes()
        .try_into()
        .expect("hash_length(32) yields 32 bytes")
}

impl HeaderV2 {
    pub fn complete_version(&self) -> u32 {
        (self.version & !VERSION_HEADER_V2_FLAG) | VERSION_HEADER_V2_FLAG
    }

    // HeaderV2 can encode its effective timestamp as an offset from time_on_wire.
    // Keep this accessor available for protocol consumers and diagnostics.
    #[allow(dead_code)]
    pub fn time(&self) -> u32 {
        if self.flags & FLAG_USE_TIME_OFFSET != 0 {
            self.time_on_wire.wrapping_add(self.time_offset)
        } else {
            self.time_on_wire
        }
    }

    pub fn asic_profile(&self) -> u8 {
        self.flags & 3
    }

    pub fn parse(b: &[u8]) -> Result<Self> {
        ensure!(
            b.len() == HEADER_V2_SIZE,
            "v2 header is {} bytes, got {}",
            HEADER_V2_SIZE,
            b.len()
        );
        let version = u32::from_le_bytes(b[0..4].try_into().unwrap());
        ensure!(
            version & VERSION_HEADER_V2_FLAG != 0,
            "not a v2 header: bit 31 of the version field is clear"
        );
        let u32at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        Ok(Self {
            version: version & !VERSION_HEADER_V2_FLAG,
            prev_blockhash: deserialize(&b[4..36])?,
            merkle_root: deserialize(&b[36..68])?,
            time_on_wire: u32at(68),
            bits: u32at(72),
            nonce: u32at(76),
            nonce2: u32at(80),
            nonce3: u32at(84),
            extranonce: b[88..104].try_into().unwrap(),
            time_offset: u32at(104),
            txcount: u16::from_le_bytes(b[108..110].try_into().unwrap()),
            flags: b[110],
            xor_key_mask_clear_bits: b[111],
            xor_key: b[112..128].try_into().unwrap(),
            height: u32at(128),
            mm_rhs: b[132..164].try_into().unwrap(),
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(HEADER_V2_SIZE);
        v.extend_from_slice(&self.complete_version().to_le_bytes());
        v.extend_from_slice(&serialize(&self.prev_blockhash));
        v.extend_from_slice(&serialize(&self.merkle_root));
        v.extend_from_slice(&self.time_on_wire.to_le_bytes());
        v.extend_from_slice(&self.bits.to_le_bytes());
        v.extend_from_slice(&self.nonce.to_le_bytes());
        v.extend_from_slice(&self.nonce2.to_le_bytes());
        v.extend_from_slice(&self.nonce3.to_le_bytes());
        v.extend_from_slice(&self.extranonce);
        v.extend_from_slice(&self.time_offset.to_le_bytes());
        v.extend_from_slice(&self.txcount.to_le_bytes());
        v.push(self.flags);
        v.push(self.xor_key_mask_clear_bits);
        v.extend_from_slice(&self.xor_key);
        v.extend_from_slice(&self.height.to_le_bytes());
        v.extend_from_slice(&self.mm_rhs);
        debug_assert_eq!(v.len(), HEADER_V2_SIZE);
        v
    }

    pub fn block_hash(&self) -> BlockHash {
        let s = self.stages();
        let mut internal = s.block_hash;
        internal.reverse();
        BlockHash::from_byte_array(internal)
    }

    /// Return intermediate values from the HeaderV2 hashing pipeline.
    ///
    /// These are useful for test vectors, implementation comparisons, and mining
    /// diagnostics even though electrs itself only consumes `block_hash`.
    pub fn stages(&self) -> Stages {
        let xor_key_hash = tagged("Bitcoin block hash PoW XOR key", &self.xor_key);

        let mut mask = [0u8; 32];
        if self.xor_key.iter().any(|b| *b != 0) {
            mask = tagged("Bitcoin block hash PoW XOR mask", &self.xor_key);
            let clear_bytes = (self.xor_key_mask_clear_bits / 8) as usize;
            for b in mask.iter_mut().take(clear_bytes) {
                *b = 0;
            }
            if clear_bytes < mask.len() {
                mask[clear_bytes] &= 0xffu8 >> (self.xor_key_mask_clear_bits % 8);
            }
        }

        let mut prev_sane = self.prev_blockhash.to_byte_array();
        prev_sane.reverse();
        let mut prev_hidden = tagged("Bitcoin prevblock header, hashed", &prev_sane);

        let mut h1p = Vec::with_capacity(119);
        h1p.extend_from_slice(&self.complete_version().to_le_bytes());
        h1p.extend_from_slice(&prev_sane);
        h1p.extend_from_slice(&self.height.to_le_bytes());
        h1p.extend_from_slice(&serialize(&self.merkle_root));
        h1p.extend_from_slice(&self.time_on_wire.to_le_bytes());
        h1p.push(0);
        h1p.extend_from_slice(&self.bits.to_le_bytes());
        h1p.extend_from_slice(&(self.txcount as u32).to_le_bytes());
        h1p.push(self.flags);
        h1p.push(self.xor_key_mask_clear_bits);
        h1p.extend_from_slice(&xor_key_hash);
        debug_assert_eq!(h1p.len(), 119);
        let h1 = tagged("Bitcoin block header 1", &h1p);

        let mut h2p = Vec::with_capacity(0x60);
        h2p.extend_from_slice(&h1);
        h2p.extend_from_slice(&[0u8; 32]);
        h2p.extend_from_slice(&self.mm_rhs);
        debug_assert_eq!(h2p.len(), 0x60);
        let h2 = tagged("Merge-mining hook", &h2p);

        let mut ss = Vec::with_capacity(52);
        ss.extend_from_slice(&0u32.to_le_bytes());
        ss.extend_from_slice(&h2);
        ss.extend_from_slice(&self.extranonce);
        debug_assert_eq!(ss.len(), 52);
        let blake2b_1 = blake2b256(&ss);

        let mut asic = Vec::with_capacity(160);
        match self.asic_profile() {
            0 => {
                prev_hidden[..6].fill(0);
                asic.extend_from_slice(&prev_hidden);
                asic.extend_from_slice(&self.nonce.to_le_bytes());
                asic.extend_from_slice(&self.nonce2.to_le_bytes());
                asic.extend_from_slice(&self.time_offset.to_le_bytes());
                asic.extend_from_slice(&self.nonce3.to_le_bytes());
                asic.extend_from_slice(&blake2b_1);
            }
            1 => {
                asic.extend_from_slice(&self.nonce.to_le_bytes());
                asic.extend_from_slice(&self.nonce2.to_le_bytes());
                asic.extend_from_slice(&self.nonce3.to_le_bytes());
                asic.extend_from_slice(&self.time_offset.to_le_bytes());
                asic.extend_from_slice(&blake2b_1);
                asic.extend_from_slice(&h2);
            }
            profile => {
                if profile == 3 {
                    asic.extend_from_slice(&[0u8; 32]);
                }
                asic.extend_from_slice(&[0u8; 48]);
                asic.extend_from_slice(&h2);
                asic.extend_from_slice(&self.nonce.to_le_bytes());
                asic.extend_from_slice(&self.nonce2.to_le_bytes());
                asic.extend_from_slice(&self.time_offset.to_le_bytes());
                asic.extend_from_slice(&self.nonce3.to_le_bytes());
                asic.extend_from_slice(&blake2b_1);
            }
        }
        let blake2b_2 = blake2b256(&asic);

        let mut block_hash = blake2b_2;
        for (byte, mask_byte) in block_hash.iter_mut().zip(mask) {
            *byte ^= mask_byte;
        }

        Stages {
            xor_key_hash,
            mask,
            h1,
            h2,
            blake2b_1,
            asic_input: asic,
            blake2b_2,
            block_hash,
        }
    }
}

/// Intermediate values from the HeaderV2 block-hash pipeline.
///
/// This diagnostic structure is intentionally retained as public API for test-vector
/// generation and cross-implementation debugging. Most fields have no production
/// caller inside electrs itself.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Stages {
    pub xor_key_hash: [u8; 32],
    pub mask: [u8; 32],
    pub h1: [u8; 32],
    pub h2: [u8; 32],
    pub blake2b_1: [u8; 32],
    pub asic_input: Vec<u8>,
    pub blake2b_2: [u8; 32],
    pub block_hash: [u8; 32],
}

pub fn visit_block_txs<V: bitcoin_slices::Visitor>(
    block: &[u8],
    header: &AnyHeader,
    visitor: &mut V,
) -> Result<()> {
    use bitcoin_slices::{bsl, Visit};

    let mut consumed = header.size();
    ensure!(
        block.len() > consumed,
        "block is {} bytes, shorter than its own {}-byte header plus a transaction count",
        block.len(),
        consumed
    );

    let total_txs = bsl::scan_len(&block[consumed..], &mut consumed)
        .map_err(|e| anyhow!("bad transaction count: {:?}", e))? as usize;

    visitor.visit_block_begin(total_txs);
    for i in 0..total_txs {
        let tx = match bsl::Transaction::visit(&block[consumed..], visitor) {
            Ok(tx) => tx,
            Err(bitcoin_slices::Error::VisitBreak) => return Ok(()),
            Err(e) => return Err(anyhow!("bad transaction at index {}: {:?}", i, e)),
        };
        consumed += tx.consumed();
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyHeader {
    V1(HeaderV1),
    V2(Box<HeaderV2>),
}

impl From<HeaderV1> for AnyHeader {
    fn from(h: HeaderV1) -> Self {
        AnyHeader::V1(h)
    }
}

impl From<HeaderV2> for AnyHeader {
    fn from(h: HeaderV2) -> Self {
        AnyHeader::V2(Box::new(h))
    }
}

impl AnyHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        match header_size(bytes)? {
            HEADER_V1_SIZE => {
                ensure!(
                    bytes.len() >= HEADER_V1_SIZE,
                    "v1 header truncated: {} bytes",
                    bytes.len()
                );
                Ok(AnyHeader::V1(deserialize(&bytes[..HEADER_V1_SIZE])?))
            }
            HEADER_V2_SIZE => {
                ensure!(
                    bytes.len() >= HEADER_V2_SIZE,
                    "v2 header truncated: {} bytes",
                    bytes.len()
                );
                Ok(HeaderV2::parse(&bytes[..HEADER_V2_SIZE])?.into())
            }
            n => bail!("impossible header size {}", n),
        }
    }

    pub fn parse_exact(bytes: &[u8]) -> Result<Self> {
        match bytes.len() {
            HEADER_V1_SIZE => Ok(AnyHeader::V1(deserialize(bytes)?)),
            HEADER_V2_SIZE => Ok(HeaderV2::parse(bytes)?.into()),
            n => bail!("not a header: {} bytes", n),
        }
    }

    pub fn parse_all(mut bytes: &[u8]) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        while !bytes.is_empty() {
            let n = header_size(bytes)?;
            ensure!(
                bytes.len() >= n,
                "trailing {} bytes, need {} for the next header",
                bytes.len(),
                n
            );
            out.push(Self::parse(&bytes[..n])?);
            bytes = &bytes[n..];
        }
        Ok(out)
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            AnyHeader::V1(h) => serialize(h),
            AnyHeader::V2(h) => h.serialize(),
        }
    }

    pub fn serialize_hex(&self) -> String {
        use bitcoin::hashes::hex::DisplayHex;
        self.serialize().to_lower_hex_string()
    }

    pub fn block_hash(&self) -> BlockHash {
        match self {
            AnyHeader::V1(h) => h.block_hash(),
            AnyHeader::V2(h) => h.block_hash(),
        }
    }

    pub fn prev_blockhash(&self) -> BlockHash {
        match self {
            AnyHeader::V1(h) => h.prev_blockhash,
            AnyHeader::V2(h) => h.prev_blockhash,
        }
    }

    // Uniform accessors are part of the AnyHeader abstraction even though current
    // electrs call sites do not need these two fields yet.
    #[allow(dead_code)]
    pub fn merkle_root(&self) -> TxMerkleNode {
        match self {
            AnyHeader::V1(h) => h.merkle_root,
            AnyHeader::V2(h) => h.merkle_root,
        }
    }

    #[allow(dead_code)]
    pub fn time(&self) -> u32 {
        match self {
            AnyHeader::V1(h) => h.time,
            AnyHeader::V2(h) => h.time(),
        }
    }

    pub fn is_v2(&self) -> bool {
        matches!(self, AnyHeader::V2(_))
    }

    pub fn size(&self) -> usize {
        if self.is_v2() {
            HEADER_V2_SIZE
        } else {
            HEADER_V1_SIZE
        }
    }
}

pub const PROTOCOL_VERSION_V2: &str = "1.8";
pub const PROTOCOL_VERSION_V1: &str = "1.4";

pub fn protocol_version(chain_has_v2: bool) -> &'static str {
    if chain_has_v2 {
        PROTOCOL_VERSION_V2
    } else {
        PROTOCOL_VERSION_V1
    }
}

pub fn may_serve_headers(chain_has_v2: bool, negotiated: Option<&str>) -> bool {
    !chain_has_v2 || negotiated == Some(PROTOCOL_VERSION_V2)
}

pub const HEADER_REFUSAL: &str =
    "this chain uses 164-byte block headers with a BLAKE2b block hash, \
     which a client below protocol 1.8 cannot read. Reconnect and negotiate 1.8. Refusing rather \
     than serving headers it would misinterpret.";

pub fn fork_point(chain: &crate::chain::Chain) -> Option<serde_json::Value> {
    if !chain.has_v2_headers() {
        return None;
    }
    let (mut lo, mut hi) = (0usize, chain.height());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        match chain.get_block_header(mid) {
            Some(h) if h.is_v2() => hi = mid,
            _ => lo = mid + 1,
        }
    }
    let header = chain.get_block_header(lo)?;
    Some(serde_json::json!({
        "height": lo,
        "hash": header.block_hash().to_string(),
        "header_bytes": HEADER_V2_SIZE,
        "block_hash": "blake2b",
    }))
}


#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin_slices::{bsl, Visit, Visitor};
    use std::ops::ControlFlow;

    const GENESIS_V1: &str = concat!(
        "010000000000000000000000000000000000000000000000000000000000000000000000",
        "3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a",
        "29ab5f49ffff001d1dac2b7c"
    );

    // Bitcoin mainnet block 1.
    const BLOCK1_V1: &str = concat!(
        "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000",
        "982051fd1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e",
        "61bc6649ffff001d01e36299"
    );

    const PROFILE0_V2: &str = concat!(
        "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
        "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577",
        "ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa9988776655443322110058020000",
        "03001c000000000000000000000000000000000040d10c008967452301efcdab89674523",
        "01efcdab8967452301efcdab8967452301efcdab"
    );

    fn decode(s: &str) -> Vec<u8> {
        Vec::from_hex(s).unwrap()
    }

    fn decode32(s: &str) -> [u8; 32] {
        decode(s).try_into().unwrap()
    }

    #[test]
    fn published_hash_vectors_cover_all_asic_profiles() {
        let vectors = [
            (
                PROFILE0_V2,
                0,
                "4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704",
            ),
            (
                concat!(
                    "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
                    "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577",
                    "ffff001d0df0ad0b44332211efcdab89ffeeddccbbaa9988776655443322110058020000",
                    "01001d00efcdab8967452301efcdab896745230141d10c008967452301efcdab89674523",
                    "01efcdab8967452301efcdab8967452301efcdab"
                ),
                1,
                "44b383821dea9af8d7d81ba7741c34ac8c07ab81ab081d8b6bf0575a787a1eef",
            ),
            (
                concat!(
                    "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
                    "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577",
                    "ffff001d0df0ad0bddccbbaaefcdab89ffeeddccbbaa9988776655443322110058020000",
                    "03001e071032547698badcfe1032547698badcfe40d10c008967452301efcdab89674523",
                    "01efcdab8967452301efcdab8967452301efcdab"
                ),
                2,
                "06fddae4eaca10b85c87a3c7ed71717fd83998a32fe13f4780722b1f5d882e76",
            ),
            (
                concat!(
                    "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
                    "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f0a8913577",
                    "ffff001d0df0ad0b44332211040302010000000000000000ffffffffffffffff58020000",
                    "03001f081032547698badcfe1032547698badcfe40d10c008967452301efcdab89674523",
                    "01efcdab8967452301efcdab8967452301efcdab"
                ),
                3,
                "e6304527536f619d3ad71b1c21a22fdef9068498acc561b4100b034373a87058",
            ),
            (
                concat!(
                    "000000a01f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
                    "00112233445566778899aabbccddeeff00102030405060708090a0b0c0d0e0f000943577",
                    "ffff001dffffffff44332211efcdab89ffeeddccbbaa9988776655443322110088776655",
                    "030018ff2222222222222222111111111111111140d10c00000000000000000000000000",
                    "0000000000000000000000000000000000000000"
                ),
                0,
                "c31b24420d67f86e524f980a24a18e88f36c821046d5288251b5d88998c69f86",
            ),
        ];

        for (wire_hex, profile, expected_hash) in vectors {
            let wire = decode(wire_hex);
            assert_eq!(wire.len(), HEADER_V2_SIZE);
            let header = HeaderV2::parse(&wire).unwrap();
            assert_eq!(header.asic_profile(), profile);
            assert_eq!(header.serialize(), wire);
            assert_eq!(header.block_hash().to_string(), expected_hash);
        }
    }

    #[test]
    fn live_activation_headers_hash_and_chain() {
        let first = decode(concat!(
            "000000a05119dc259b59eaefbccf48ecc15bfd50c499d9d65b500b361b1b600000000000",
            "63be46460c5e75edfe6e1fba731e3fc096396af99c299e70625484ffc6f9184101fb896a",
            "ffff001d986cd88b510d792301fb896a00000000b14cf00d010000000000000000000000",
            "0f0000000000000000000000000000000000000021480200000000000000000000000000",
            "0000000000000000000000000000000000000000"
        ));
        let second = decode(concat!(
            "000000a0826d73fd08c604780d8d8fcfb1adedc7bcef8b0cdc33c92904f6680000000000",
            "a56c8509d818afaadcea27a066a820f5c8ac610bb0f8bc297528a52e8bf6c2d202fb896a",
            "ffff001dbe7b778a800e881f02fb896a00000000b10cf00d010000000000000000000000",
            "010000000000000000000000000000000000000022480200000000000000000000000000",
            "0000000000000000000000000000000000000000"
        ));

        let first = HeaderV2::parse(&first).unwrap();
        let second = HeaderV2::parse(&second).unwrap();
        assert_eq!(first.height, 149_537);
        assert_eq!(second.height, 149_538);
        assert_eq!(
            first.block_hash().to_string(),
            "000000000068f60429c933dc0c8befbcc7edadb1cf8f8d0d7804c608fd736d82"
        );
        assert_eq!(
            second.block_hash().to_string(),
            "000000000008b8d8f1ce043359100c971e3e0db6bb8ae8ac8618f554564d9177"
        );
        assert_eq!(second.prev_blockhash, first.block_hash());
    }

    #[test]
    fn v2_effective_time_respects_offset_flag() {
        let mut header = HeaderV2::parse(&decode(PROFILE0_V2)).unwrap();
        assert_eq!(header.time_on_wire, 1_999_999_400);
        assert_eq!(header.time_offset, 600);
        assert_ne!(header.flags & FLAG_USE_TIME_OFFSET, 0);
        assert_eq!(header.time(), 2_000_000_000);

        header.flags &= !FLAG_USE_TIME_OFFSET;
        assert_eq!(header.time(), header.time_on_wire);

        header.flags |= FLAG_USE_TIME_OFFSET;
        header.time_on_wire = u32::MAX - 1;
        header.time_offset = 10;
        assert_eq!(header.time(), 8, "timestamp addition is defined to wrap");
    }

    #[test]
    fn v2_stages_match_published_profile0_vector() {
        let header = HeaderV2::parse(&decode(PROFILE0_V2)).unwrap();
        let stages = header.stages();

        assert_eq!(
            stages.xor_key_hash,
            decode32("86e4855b51daf0932719011a6565a5908aef105fc6f8b85a23601de43865f4db")
        );
        assert_eq!(stages.mask, [0u8; 32]);
        assert_eq!(
            stages.h1,
            decode32("4ff7ec7f24f6935064cb962ec8cc0c947d60621cc22c5ba8516b0b995cd0c01b")
        );
        assert_eq!(
            stages.h2,
            decode32("ab5becb2336a3701557b0f6e33de39bd333072b8494c7c60952a8e8a636565e3")
        );
        assert_eq!(
            stages.blake2b_1,
            decode32("7e6326906eaa52fe59e03a14f1dfb8dd5d6e78497e56a8a6e4f4fb4d385e43db")
        );
        assert_eq!(
            stages.asic_input,
            decode(concat!(
                "000000000000943aff74219e1f45899abfdf536373c0f2fc92e6fe58335cd0ad",
                "0df0ad0b4433221158020000efcdab897e6326906eaa52fe59e03a14f1dfb8dd",
                "5d6e78497e56a8a6e4f4fb4d385e43db"
            ))
        );
        assert_eq!(
            stages.blake2b_2,
            decode32("4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704")
        );
        assert_eq!(stages.block_hash, stages.blake2b_2);
        assert_eq!(
            header.block_hash().to_string(),
            "4b495dcf05d70a49785b799b22284fbcd9dd1209237c53c87e4674b15587d704"
        );
    }

    #[test]
    fn any_header_accessors_match_real_bitcoin_headers() {
        let genesis = AnyHeader::parse_exact(&decode(GENESIS_V1)).unwrap();
        assert_eq!(
            genesis.block_hash().to_string(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(
            genesis.prev_blockhash().to_string(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            genesis.merkle_root().to_string(),
            "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
        );
        assert_eq!(genesis.time(), 1_231_006_505);

        let block1 = AnyHeader::parse_exact(&decode(BLOCK1_V1)).unwrap();
        assert_eq!(
            block1.block_hash().to_string(),
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        );
        assert_eq!(block1.prev_blockhash(), genesis.block_hash());
        assert_eq!(
            block1.merkle_root().to_string(),
            "0e3e2357e806b6cdb1f70b54c3a3a17b6714ee1f0e68bebb44a74b1efd512098"
        );
        assert_eq!(block1.time(), 1_231_469_665);
        assert_eq!(block1.serialize_hex(), BLOCK1_V1);
    }

    #[test]
    fn mixed_v1_v2_header_stream_roundtrips() {
        let v1 = decode(GENESIS_V1);
        let v2 = decode(PROFILE0_V2);
        let mut stream = Vec::new();
        stream.extend_from_slice(&v1);
        stream.extend_from_slice(&v2);
        stream.extend_from_slice(&v1);

        let headers = AnyHeader::parse_all(&stream).unwrap();
        assert_eq!(headers.len(), 3);
        assert!(!headers[0].is_v2());
        assert!(headers[1].is_v2());
        assert!(!headers[2].is_v2());
        let roundtrip: Vec<u8> = headers.iter().flat_map(AnyHeader::serialize).collect();
        assert_eq!(roundtrip, stream);
    }

    #[test]
    fn exact_parser_uses_db_row_length_for_legacy_v1() {
        let mut legacy_v1 = decode(GENESIS_V1);
        legacy_v1[3] |= 0x80;
        assert_eq!(header_size(&legacy_v1).unwrap(), HEADER_V2_SIZE);
        assert!(!AnyHeader::parse_exact(&legacy_v1).unwrap().is_v2());

        let mut malformed_v2 = decode(PROFILE0_V2);
        malformed_v2[3] &= 0x7f;
        assert!(AnyHeader::parse_exact(&malformed_v2).is_err());
        assert!(AnyHeader::parse_all(&decode(PROFILE0_V2)[..HEADER_V2_SIZE - 1]).is_err());
    }

    #[test]
    fn v2_block_transactions_start_after_164_byte_header() {
        #[derive(Default)]
        struct Counter {
            announced: usize,
            visited: usize,
        }

        impl Visitor for Counter {
            fn visit_block_begin(&mut self, total_transactions: usize) {
                self.announced = total_transactions;
            }

            fn visit_transaction(&mut self, _tx: &bsl::Transaction) -> ControlFlow<()> {
                self.visited += 1;
                ControlFlow::Continue(())
            }
        }

        let v1_block = bitcoin_test_data::blocks::mainnet_702861();
        let mut expected = Counter::default();
        bsl::Block::visit(v1_block, &mut expected).unwrap();
        assert!(expected.visited > 0);

        let mut v2_header = HeaderV2::parse(&decode(PROFILE0_V2)).unwrap();
        v2_header.txcount = expected.announced.try_into().unwrap();
        let header: AnyHeader = v2_header.into();
        let mut v2_block = header.serialize();
        v2_block.extend_from_slice(&v1_block[HEADER_V1_SIZE..]);

        let mut actual = Counter::default();
        visit_block_txs(&v2_block, &header, &mut actual).unwrap();
        assert_eq!(actual.announced, expected.announced);
        assert_eq!(actual.visited, expected.visited);

        struct BreakAfterOne(usize);
        impl Visitor for BreakAfterOne {
            fn visit_transaction(&mut self, _tx: &bsl::Transaction) -> ControlFlow<()> {
                self.0 += 1;
                ControlFlow::Break(())
            }
        }
        let mut breaker = BreakAfterOne(0);
        visit_block_txs(&v2_block, &header, &mut breaker).unwrap();
        assert_eq!(breaker.0, 1, "visitor break must not become a parse failure");
    }

    #[test]
    fn any_header_keeps_v2_payload_boxed() {
        use std::mem::size_of;

        assert_eq!(size_of::<HeaderV2>(), HEADER_V2_SIZE);
        assert!(size_of::<AnyHeader>() <= size_of::<bitcoin::block::Header>() + 8);
    }

    #[test]
    fn electrum_protocol_gates_v2_header_serving() {
        assert_eq!(protocol_version(false), PROTOCOL_VERSION_V1);
        assert_eq!(protocol_version(true), PROTOCOL_VERSION_V2);
        assert!(may_serve_headers(false, None));
        assert!(may_serve_headers(false, Some(PROTOCOL_VERSION_V1)));
        assert!(!may_serve_headers(true, None));
        assert!(!may_serve_headers(true, Some(PROTOCOL_VERSION_V1)));
        assert!(may_serve_headers(true, Some(PROTOCOL_VERSION_V2)));
    }
}
