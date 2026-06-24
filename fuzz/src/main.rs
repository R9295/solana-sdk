//! Bidirectional (deserialize ⇄ serialize) wincode roundtrip fuzz harness.
//!
//! Every workspace type that hand-writes a `wincode::SchemaWrite` impl — i.e. a
//! *custom* serializer, as opposed to the `#[derive(SchemaWrite)]`d one — is
//! exercised here (find them with `rg 'impl.*SchemaWrite.*for'`). For each type,
//! within this single harness, the raw fuzz bytes are:
//!
//!   1. deserialized into the type's value,
//!   2. re-serialized back to bytes (`b1`),
//!   3. if `b1` is exactly as long as the input, asserted to reproduce the input
//!      byte-for-byte — the input was one exact canonical encoding, so this is
//!      the `deserialize_exact` roundtrip, and
//!   4. always asserted to be a stable fixpoint under another
//!      deserialize/serialize cycle (`serialize ∘ deserialize ∘ serialize ==
//!      serialize`), which also covers inputs that carried trailing bytes.
//!
//! Most of these types are *schema markers*: their `SchemaRead::Dst` /
//! `SchemaWrite::Src` is a separate value type (e.g. `Leb128Int<u64>` reads and
//! writes a `u64`, `CompactTowerSync` a `TowerSync`). They are therefore driven
//! through wincode's trait-level `Deserialize`/`Serialize` API rather than the
//! free `wincode::{deserialize, serialize}` functions, which require
//! `Dst == Src == Self`.

use solana_loader_v3_interface::instruction::OptionalTrailingBool;
use solana_message::{v1, VersionedMessage};
use solana_short_vec::ShortU16;
use solana_transaction::versioned::VersionedTransaction;
use solana_vote_interface::state::wincode_compact::{CompactTowerSync, CompactVoteStateUpdate};
use solana_wincode_varint::Leb128Int;

/// Roundtrip-fuzz `$data` interpreted as the wincode schema `$schema`.
///
/// Does nothing when the bytes do not deserialize; otherwise enforces both the
/// exact-length roundtrip (3) and the canonical fixpoint (4) described above.
macro_rules! roundtrip {
    ($schema:ty, $data:expr) => {{
        let input: &[u8] = $data;
        if let Ok(value) = <$schema as wincode::Deserialize<'_>>::deserialize(input) {
            let b1 = <$schema as wincode::Serialize>::serialize(&value)
                .expect(concat!("serialize after deserialize failed: ", stringify!($schema)));
            // (3) `deserialize_exact`: when no trailing bytes were consumed, the
            // canonical re-encoding must equal the input exactly.
            if b1.len() == input.len() {
                assert_eq!(
                    b1.as_slice(),
                    input,
                    concat!("deserialize_exact roundtrip mismatch: ", stringify!($schema)),
                );
            }
            // (4) The canonical form must round-trip to itself.
            let value2 = <$schema as wincode::Deserialize<'_>>::deserialize(b1.as_slice()).expect(
                concat!("re-deserialize of canonical bytes failed: ", stringify!($schema)),
            );
            let b2 = <$schema as wincode::Serialize>::serialize(&value2)
                .expect(concat!("re-serialize failed: ", stringify!($schema)));
            assert_eq!(b1, b2, concat!("serialization not idempotent: ", stringify!($schema)));
        }
    }};
}

fn main() {
    ziggy::fuzz!(|data: &[u8]| {
        // Composite message / transaction types (value type == the type itself).
        roundtrip!(VersionedMessage, data);
        roundtrip!(VersionedTransaction, data);
        roundtrip!(v1::Message, data);

        // Vote "compact" schema markers (value types: VoteStateUpdate / TowerSync).
        roundtrip!(CompactVoteStateUpdate, data);
        roundtrip!(CompactTowerSync, data);

        // LEB128 varint schema markers (value types: u16 / u32 / u64).
        roundtrip!(Leb128Int<u16>, data);
        roundtrip!(Leb128Int<u32>, data);
        roundtrip!(Leb128Int<u64>, data);

        // short-vec compact length prefix (value type: ShortU16).
        roundtrip!(ShortU16, data);

        // loader-v3 optional trailing bool (value type: bool), for both defaults.
        roundtrip!(OptionalTrailingBool<false>, data);
        roundtrip!(OptionalTrailingBool<true>, data);
    });
}
