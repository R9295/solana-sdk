#![no_main]

use libfuzzer_sys::fuzz_target;

// TODO: simplify this with deserialize_exact once wincode is updated
macro_rules! fuzz_roundtrip {
    ($data:expr, $schema:ty) => {{
        let mut reader: &[u8] = $data;
        if let Ok(value) =
            <$schema as wincode::SchemaRead<'_, wincode::config::DefaultConfig>>::get(&mut reader)
        {
            // Require the input to be fully consumed. Trailing bytes would be
            // dropped on re-serialization, so they can never round-trip.
            if reader.is_empty() {
                let serialized = <$schema as wincode::Serialize>::serialize(&value)
                    .expect("serialize should succeed");
                assert_eq!(
                    $data,
                    serialized.as_slice(),
                    "deserialize -> serialize != original_data for schema {}\nserialized {:?}\noriginal   {:?}",
                    stringify!($schema),
                    serialized,
                    $data,
                );

                // Our serialized output must itself deserialize and re-serialize
                // to the same bytes.
                let mut reader = serialized.as_slice();
                let reparsed =
                    <$schema as wincode::SchemaRead<'_, wincode::config::DefaultConfig>>::get(
                        &mut reader,
                    )
                    .expect("roundtrip deserialize should succeed");
                let reserialized = <$schema as wincode::Serialize>::serialize(&reparsed)
                    .expect("roundtrip serialize should succeed");
                assert_eq!(
                    serialized,
                    reserialized,
                    "roundtrip serialize mismatch for schema {}",
                    stringify!($schema),
                );
            }
        }
    }};
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, payload)) = data.split_first() else {
        return;
    };
    match selector {
        0 => fuzz_roundtrip!(payload, solana_message::v1::Message),
        1 => fuzz_roundtrip!(payload, solana_message::VersionedMessage),
        2 => fuzz_roundtrip!(payload, solana_transaction::versioned::VersionedTransaction),
        3 => fuzz_roundtrip!(payload, solana_short_vec::ShortU16),
        4 => fuzz_roundtrip!(payload, solana_wincode_varint::Leb128Int<u16>),
        5 => fuzz_roundtrip!(payload, solana_wincode_varint::Leb128Int<u32>),
        6 => fuzz_roundtrip!(payload, solana_wincode_varint::Leb128Int<u64>),
        7 => fuzz_roundtrip!(
            payload,
            solana_vote_interface::state::wincode_compact::CompactVoteStateUpdate
        ),
        8 => fuzz_roundtrip!(
            payload,
            solana_vote_interface::state::wincode_compact::CompactTowerSync
        ),
        // Derived-schema payloads with custom `#[wincode(with = "...")]` fields.
        9 => fuzz_roundtrip!(payload, solana_transaction::Transaction),
        10 => fuzz_roundtrip!(payload, solana_vote_interface::instruction::VoteInstruction),
        _ => {}
    }
});
