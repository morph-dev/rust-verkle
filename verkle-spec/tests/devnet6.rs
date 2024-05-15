use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use hex::FromHex;
use keccak_hash::{keccak, KECCAK_EMPTY};
use once_cell::sync::Lazy;
use serde::Deserialize;
use serde_json::json;
use std::{fs::File, io::BufReader, str::FromStr, sync::Mutex};
use verkle_spec::{
    addr20_to_addr32, code::chunkify_code, Address20, Code, Hasher, Header, Storage, H256, U256,
};
use verkle_trie::{database::memory_db::MemoryDb, Trie, TrieTrait, Value, VerkleConfig};

const GENESIS_FILEPATH: &str = "assets/devnet6_genesis.json";
const STATE_ROOT: &str = "0x1fbf85345a3cbba9a6d44f991b721e55620a22397c2a93ee8d5011136ac300ee";

pub struct DefaultHasher;

impl Hasher for DefaultHasher {}

pub static CONFIG: Lazy<Mutex<VerkleConfig<MemoryDb>>> =
    Lazy::new(|| Mutex::new(VerkleConfig::new(MemoryDb::new())));

fn to_trie_value(u256: U256) -> Value {
    let mut value = Value::default();
    u256.to_little_endian(value.as_mut_slice());
    value
}

#[test]
fn state_root() -> Result<()> {
    let file = File::open(GENESIS_FILEPATH)?;
    let genesis_config: serde_json::Value = serde_json::from_reader(BufReader::new(file))?;
    let genesis_config = genesis_config.as_object().unwrap();
    let alloc = genesis_config.get("alloc").unwrap().as_object().unwrap();

    let mut trie = Trie::new(CONFIG.lock().unwrap().clone());

    for (address, account_state) in alloc {
        let address = addr20_to_addr32(Address20::from_str(address)?);
        let account_state = account_state.as_object().unwrap();

        let header = Header::new::<DefaultHasher>(address);

        let balance =
            U256::from_str_radix(account_state.get("balance").unwrap().as_str().unwrap(), 10)?;
        let nonce = U256::from_str_radix(
            account_state
                .get("nonce")
                .unwrap_or(&json!("0"))
                .as_str()
                .unwrap(),
            10,
        )?;

        // println!("Creating Account: address={address:?} balance={balance} nonce={nonce}");
        trie.insert(
            [
                (header.version().0, to_trie_value(U256::zero())),
                (header.balance().0, to_trie_value(balance)),
                (header.nonce().0, to_trie_value(nonce)),
            ]
            .into_iter(),
        );

        match account_state.get("code") {
            Some(code) => {
                let code = code.as_str().unwrap();
                let code = code.strip_prefix("0x").unwrap_or(code);
                let code = <Vec<u8>>::from_hex(code)?;

                // println!(
                //     "\tCode: code_hash={:?} code_size={}",
                //     keccak(&code),
                //     code.len()
                // );
                trie.insert(
                    [
                        (header.code_keccak().0, keccak(&code).0),
                        (header.code_size().0, to_trie_value(U256::from(code.len()))),
                    ]
                    .into_iter(),
                );
                trie.insert(chunkify_code(code).into_iter().enumerate().map(
                    |(chunk_id, code_chunk)| {
                        (
                            Code::new::<DefaultHasher>(address, U256::from(chunk_id))
                                .code_chunk()
                                .0,
                            code_chunk,
                        )
                    },
                ));

                let Some(storage) = account_state.get("storage") else {
                    continue;
                };

                let storage = storage.as_object().unwrap();
                trie.insert(storage.iter().map(|(storage_key, storage_value)| {
                    let storage_key = U256::from_str(storage_key).unwrap();
                    let storage_slot =
                        Storage::new::<DefaultHasher>(address, storage_key).storage_slot();
                    let storage_value = U256::deserialize(storage_value).unwrap();
                    // println!(
                    //     "\tStorage:  key={storage_key:#x} slot={storage_slot:?} value={storage_value:#x}"
                    // );
                    (storage_slot.0, to_trie_value(storage_value))
                }));
            }
            None => {
                // println!("\tCode: code_hash={KECCAK_EMPTY:?} code_size=0");
                trie.insert_single(header.code_keccak().0, KECCAK_EMPTY.0);
                // TODO: maybe uncommend code size?
                // trie.insert_single(header.code_size().0, to_trie_value(U256::zero()));
            }
        }
    }

    let mut root_hash = H256::zero();
    trie.root_hash()
        .serialize_compressed(root_hash.0.as_mut_slice())?;
    assert_eq!(root_hash, H256::from_str(STATE_ROOT)?);

    Ok(())
}
