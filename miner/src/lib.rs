use hex::{self, decode, encode};
use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
use sha2::{Digest as DG, Sha256};
use structs::GasedTransaction;
use std::collections::{HashMap,HashSet};
use std::fs::File;
use std::io::prelude::*;
use std::time::{SystemTime, UNIX_EPOCH};
use std::vec;

pub mod structs;
pub mod utils;
use crate::structs::{Transaction, Vin};
use crate::utils::{compute_hash160, double_sha256, print_hex_string, ripemd160_hash};
// Define the Bitcoin opcodes and their corresponding operations
const _OPCODES: &[(&str, u8)] = &[
    ("OP_0", 0x00),
    ("OP_PUSHDATA1", 0x4c),
    ("OP_PUSHDATA2", 0x4d),
    ("OP_PUSHDATA4", 0x4e),
    ("OP_1", 0x51),
    ("OP_DUP", 0x76),
    ("OP_HASH160", 0xa9),
    ("OP_EQUALVERIFY", 0x88),
    ("OP_CHECKSIG", 0xac),
];

const DIFFICULTY_TARGET: [u8; 32] = [
    0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

// Utils

fn prepare_signature_message(transaction: &Transaction, input_index: usize) -> Vec<u8> {
    let mut message: Vec<u8> = Vec::new();

    // Serialize transaction version
    message.extend(&transaction.version.to_le_bytes());

    // Serialize input count
    let input_count_bytes = get_compact_size(transaction.vin.len());
    message.extend(&input_count_bytes);

    // Serialize inputs
    for (i, input) in transaction.vin.iter().enumerate() {
        let mut txid = hex::decode(input.txid.clone()).unwrap();
        txid.reverse();
        message.extend(txid);
        message.extend(&input.vout.to_le_bytes());

        if i == input_index {
            // For the input being verified, replace the signature script with an empty script
            let scriptpubkey_bytes = hex::decode(input.prevout.scriptpubkey.clone()).unwrap();
            let script_len_bytes = get_compact_size(scriptpubkey_bytes.len());
            message.extend(&script_len_bytes);
            message.extend(scriptpubkey_bytes.iter());
        } else {
            let script_len_bytes = get_compact_size(0);
            message.extend(&script_len_bytes);
        }

        message.extend(&input.sequence.to_le_bytes());
    }

    // Serialize output count

    let output_count_bytes = get_compact_size(transaction.vout.len());
    message.extend(&output_count_bytes);
    for (_i, output) in transaction.vout.iter().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.as_mut().copy_from_slice(&output.value.to_le_bytes());
        message.extend_from_slice(&bytes);
        let pubkey_bytes = hex::decode(output.scriptpubkey.clone()).unwrap();
        let script_len_bytes = get_compact_size(pubkey_bytes.len());
        message.extend(&script_len_bytes);
        message.extend(&pubkey_bytes);
    }

    // Serialize outputs (omitted for brevity)

    // Serialize locktime
    message.extend(&transaction.locktime.to_le_bytes());

    // Serialize SIGHASH flag
    let sighash_type: i32 = 1;
    message.extend(&sighash_type.to_le_bytes());

    // Hash the message
    // println!("{:?}", transaction);
    let mut sha256 = Sha256::new();
    // print_hex_string(&message);
    sha256.update(&message);
    let hash = sha256.finalize_reset();

    sha256.update(&hash);
    let final_hash = sha256.finalize();
    // print_hex_string(&final_hash.to_vec());

    final_hash.to_vec()
}

fn construct_p2wpkh_script(pubkey: &[u8]) -> Vec<u8> {
    let hashed_pubkey = compute_hash160(pubkey);

    let mut script = Vec::with_capacity(22);
    script.push(0x00);
    script.push(0x14);
    script.extend_from_slice(&hashed_pubkey);
    script
}

fn construct_p2wpkh_scriptcode(pubkey: &[u8]) -> Vec<u8> {
    let hashed_pubkey = compute_hash160(pubkey);

    let mut script = Vec::new();
    script.push(0x19);
    script.push(0x76);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(&hashed_pubkey);
    script.push(0x88);
    script.push(0xac);
    script
}

pub fn get_compact_size(len: usize) -> Vec<u8> {
    let script_len = len;
    if script_len <= 0xfc {
        vec![script_len as u8]
    } else if script_len <= 0xffff {
        let mut compact_size = vec![0xfd];
        compact_size.extend_from_slice(&(script_len as u16).to_le_bytes());
        compact_size
    } else if script_len <= 0xffff_ffff {
        let mut compact_size = vec![0xfe];
        compact_size.extend_from_slice(&(script_len as u32).to_le_bytes());
        compact_size
    } else {
        let mut compact_size = vec![0xff];
        compact_size.extend_from_slice(&(script_len as u64).to_le_bytes());
        compact_size
    }
}

// Script Validation
pub fn validate_script(script: &str, message: Vec<u8>) -> Result<(), String> {
    let mut opcode_map: HashMap<String, u8> = HashMap::new();

    // Define the Bitcoin opcodes and their corresponding operations
    let opcodes = [
        ("OP_0", 0x00),
        ("OP_PUSHDATA1", 0x4c),
        ("OP_PUSHDATA2", 0x4d),
        ("OP_PUSHDATA4", 0x4e),
        ("OP_1", 0x51),
        ("OP_DUP", 0x76),
        ("OP_HASH160", 0xa9),
        ("OP_EQUALVERIFY", 0x88),
        ("OP_CHECKSIG", 0xac),
    ];

    // Add hardcoded opcodes to the map
    for (opcode, value) in opcodes {
        opcode_map.insert(opcode.to_string(), value);
    }

    // Add OP_PUSHBYTES_{n} opcodes to the map
    for n in 1..=75 {
        let opcode = format!("OP_PUSHBYTES_{}", n);
        opcode_map.insert(opcode, n as u8);
    }

    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut iter = script.split_whitespace();
    while let Some(token) = iter.next() {
        if let Some(opcode) = opcode_map.get(token) {
            // Verify the opcode
            match *opcode {
                // Handle OP_PUSHBYTES_{n} opcodes
                n @ 1..=75 => {
                    let data = iter
                        .next()
                        .ok_or_else(|| format!("{}: missing data", token))?;
                    if data.len() != 2 * n as usize {
                        return Err(format!(
                            "{}: data length mismatch (expected {}, found {}, string {})",
                            token,
                            n,
                            data.len(),
                            data
                        ));
                    }
                    match decode(data) {
                        Ok(bytes) => stack.push(bytes),
                        Err(_) => {
                            // Handle invalid hexadecimal string
                            panic!("Invalid hexadecimal string");
                        }
                    }
                }
                0x00 => stack.push(Vec::new()),
                0x76 => {
                    if let Some(data) = stack.pop() {
                        stack.push(data.clone());
                        stack.push(data);
                    } else {
                        return Err("OP_DUP: stack underflow".to_string());
                    }
                }
                0xa9 => {
                    if let Some(data) = stack.pop() {
                        let hashed = compute_hash160(&data);
                        stack.push(hashed.to_vec());
                    } else {
                        return Err("OP_HASH160: stack underflow".to_string());
                    }
                }
                0x88 => {
                    if let (Some(a), Some(b)) = (stack.pop(), stack.pop()) {
                        if a != b {
                            return Err(format!("Not equal after Hash160 {:?} {:?}", a, b));
                        }
                    } else {
                        return Err("OP_EQUALVERIFY: stack underflow".to_string());
                    }
                }
                0xac => {
                    if let (Some(pubkey), Some(signature)) = (stack.pop(), stack.pop()) {
                        let mut sign = signature.clone();
                        sign.pop();
                        let context = Secp256k1::new();

                        // Construct the message from the twice SHA-256 hashed data
                        let msg = Message::from_digest_slice(&message).expect("Invalid message");

                        // Parse the signature
                        let sig = Signature::from_der(sign.as_slice()).expect("Invalid signature");

                        // Parse the public key
                        let pub_key =
                            PublicKey::from_slice(pubkey.as_slice()).expect("Invalid public key");

                        // Verify the signature against the message and public key
                        let result = context.verify_ecdsa(&msg, &sig, &pub_key).is_ok();
                        if result {
                            return Ok(());
                        } else {
                            return Err("Invalid Signature".to_string());
                        }
                    } else {
                        return Err("OP_CHECKSIG: stack underflow".to_string());
                    }
                }
                _ => return Err(format!("Invalid opcode: {}", token)),
            }
        } else {
            return Err(format!("Invalid opcode: {}", token));
        }
    }

    Ok(())
}

pub fn validate_p2wpkh(
    transaction: &Transaction,
    vinput: &Vin,
    input_index: usize,
) -> Result<(), String> {
    match &vinput.witness {
        Some(witness) => {
            if witness.0.len() < 2 {
                return Err("Less than 2 witnesses".to_string());
            } else {
                let signature = witness.0[0].clone();
                let mut sign = decode(&signature).unwrap();
                sign.pop();
                let public_key = witness.0[1].clone();

                // Preliminary test
                let pubkey_bytes = decode(&public_key).unwrap();
                let script = construct_p2wpkh_script(&pubkey_bytes);
                let scriptpubkey_bytes = decode(vinput.prevout.scriptpubkey.clone()).unwrap();
                if scriptpubkey_bytes != script {
                    return Err("Invalid Public Key/ScriptPubKey".to_string());
                }
                let mut message: Vec<u8> = Vec::new();
                message.extend(&transaction.version.to_le_bytes());
                let mut prevouts: Vec<u8> = Vec::new();
                let mut seqs: Vec<u8> = Vec::new();
                let mut curr_input: Vec<u8> = Vec::new();
                for (i, input) in transaction.vin.iter().enumerate() {
                    let mut txid = hex::decode(input.txid.clone()).unwrap();
                    txid.reverse();
                    prevouts.extend(&txid);
                    prevouts.extend(&input.vout.to_le_bytes());
                    seqs.extend(&input.sequence.to_le_bytes());
                    if i == input_index {
                        curr_input.extend(txid);
                        curr_input.extend(&input.vout.to_le_bytes());
                    }
                }
                let hash_prevout = double_sha256(&prevouts);
                let hash_seqs = double_sha256(&seqs);
                message.extend(hash_prevout);
                message.extend(hash_seqs);
                message.extend(curr_input);
                let scriptcode = construct_p2wpkh_scriptcode(&pubkey_bytes);
                message.extend(scriptcode);
                let mut bytes = [0u8; 8];
                bytes
                    .as_mut()
                    .copy_from_slice(&vinput.prevout.value.to_le_bytes());
                message.extend_from_slice(&bytes);
                message.extend(&vinput.sequence.to_le_bytes());
                let mut outs: Vec<u8> = Vec::new();
                for (_i, output) in transaction.vout.iter().enumerate() {
                    let mut bytes = [0u8; 8];
                    bytes.as_mut().copy_from_slice(&output.value.to_le_bytes());
                    outs.extend_from_slice(&bytes);
                    let pubkey_bytes = hex::decode(output.scriptpubkey.clone()).unwrap();
                    let script_len_bytes = get_compact_size(pubkey_bytes.len());
                    outs.extend(&script_len_bytes);
                    outs.extend(&pubkey_bytes);
                }
                let hash_out = double_sha256(&outs);
                message.extend(hash_out);
                message.extend(&transaction.locktime.to_le_bytes());

                // Serialize SIGHASH flag
                let sighash_type: i32 = 1;
                message.extend(&sighash_type.to_le_bytes());
                let final_message = double_sha256(&message);
                let context = Secp256k1::new();
                let msg = Message::from_digest_slice(&final_message).expect("Invalid message");

                // Parse the signature
                let sig = Signature::from_der(sign.as_slice())
                    .expect("Invalid signature. Unable to parse");

                // Parse the public key
                let pub_key =
                    PublicKey::from_slice(pubkey_bytes.as_slice()).expect("Invalid public key");

                // Verify the signature against the message and public key
                let result = context.verify_ecdsa(&msg, &sig, &pub_key).is_ok();
                if result {
                    return Ok(());
                } else {
                    // print_hex_string(&message);
                    // print_hex_string(&final_message);
                    // println!("{:?}", transaction);
                    return Err("Invalid Signature".to_string());
                }
            }
        }
        None => return Err("No witness found".to_string()),
    }
}

pub fn validate_transaction(transaction: &Transaction) -> Result<bool, String> {
    let mut flag = false;
    let mut _temp = 7;
    for (i, vin) in transaction.vin.iter().enumerate() {
        if vin.prevout.scriptpubkey_type == "p2pkh" {
            let script = format!("{} {}", vin.scriptsig_asm, vin.prevout.scriptpubkey_asm);
            let message = prepare_signature_message(transaction, i);
            match validate_script(&script, message) {
                Ok(()) => match &vin.witness {
                    Some(_wit) => flag = true,
                    None => _temp += 1,
                },
                Err(err) => return Err(err),
            }
        } else if vin.prevout.scriptpubkey_type == "v0_p2wpkh" {
            match validate_p2wpkh(transaction, vin, i) {
                Ok(()) => match &vin.witness {
                    Some(_wit) => flag = true,
                    None => _temp += 1,
                },
                Err(err) => return Err(err),
            }
        }
        else if vin.prevout.scriptpubkey_type == "v1_p2tr" {
            // println!("P2TR transactions are valid!");
            match &vin.witness {
                Some(_wit) => flag = true,
                None => _temp += 1,
            }
        }
        else {
            return Err("Transaction not supported for now".to_string());
        }
    }
    return Ok(flag);
}


pub fn serialize_transation(transaction: &Transaction, issegwit: bool) -> Vec<u8> {
    let mut serialized_data = Vec::new();

    // Serialize the transaction header
    serialized_data.extend(&transaction.version.to_le_bytes());
    if issegwit {
        serialized_data.push(0x00);
        serialized_data.push(0x01);
    }

    serialized_data.extend(&get_compact_size(transaction.vin.len()));
    // Serialize the inputs
    for vin in &transaction.vin {
        // Serialize the txid and vout
        let mut tx_id = decode(&vin.txid).unwrap();
        tx_id.reverse();
        serialized_data.extend(tx_id);
        serialized_data.extend(&vin.vout.to_le_bytes());
        let scriptsig_bytes = decode(&vin.scriptsig).unwrap();
        serialized_data.extend(get_compact_size(scriptsig_bytes.len()));

        // Serialize the scriptsig (for non-SegWit inputs)
        if vin.witness.is_none() {
            serialized_data.extend(scriptsig_bytes);
        }

        // Serialize the sequence
        serialized_data.extend(&vin.sequence.to_le_bytes());
    }

    serialized_data.extend(&get_compact_size(transaction.vout.len()));
    // Serialize the outputs
    for vout in &transaction.vout {
        // Serialize the value
        serialized_data.extend(&vout.value.to_le_bytes());

        // Serialize the scriptpubkey
        let scriptpubkey = hex::decode(&vout.scriptpubkey).unwrap();
        serialized_data.extend(&get_compact_size(scriptpubkey.len()));
        serialized_data.extend(&scriptpubkey);
    }

    if issegwit {
        for vin in &transaction.vin {
            match &vin.witness {
                Some(wit) => {
                    serialized_data.extend(&get_compact_size(wit.0.len()));
                    for item in &wit.0 {
                        let witness_item = decode(item).unwrap();
                        serialized_data.extend(&get_compact_size(witness_item.len()));
                        serialized_data.extend(&witness_item);
                    }
                }
                None => serialized_data.push(0x00),
            }
        }
    }

    serialized_data.extend(&transaction.locktime.to_le_bytes());

    serialized_data
}

pub fn create_coinbase_trx(wtx_merkle: Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    let mut next_half = wtx_merkle.clone();
    next_half.extend(
        decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
    );
    let sha_next = double_sha256(&next_half);
    let part = encode(sha_next);
    // 01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804233fa04e028b12ffffffff0130490b2a010000004341047eda6bd04fb27cab6e7c28c99b94977f073e912f25d1ff7165d9c95cd9bbe6da7e7ad7f2acb09e0ced91705f7616af53bee51a238b7dc527f2be0aa60469d140ac00000000
    let coinbase_trx = format!("010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9ed{}0120000000000000000000000000000000000000000000000000000000000000000000000000",part);
    let coinbase_txid_data = format!("01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100ffffffff02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac0000000000000000266a24aa21a9ed{}00000000",part);
    let trans_data = decode(coinbase_trx).unwrap();
    let txid = double_sha256(&decode(coinbase_txid_data).unwrap());
    return (trans_data, txid);
}

pub fn calculate_txid(transaction: &Transaction) -> Vec<u8> {
    let mut serialized_data = Vec::new();

    // Serialize the transaction header
    serialized_data.extend(&transaction.version.to_le_bytes());
    serialized_data.extend(&get_compact_size(transaction.vin.len()));
    // Serialize the inputs
    for vin in &transaction.vin {
        // Serialize the txid and vout
        let mut tx_id = decode(&vin.txid).unwrap();
        tx_id.reverse();
        serialized_data.extend(tx_id);
        serialized_data.extend(&vin.vout.to_le_bytes());

        let scriptsig_bytes = decode(&vin.scriptsig).unwrap();
        serialized_data.extend(get_compact_size(scriptsig_bytes.len()));

        // Serialize the scriptsig (for non-SegWit inputs)
        if vin.witness.is_none() {
            serialized_data.extend(scriptsig_bytes);
        }

        // Serialize the sequence
        serialized_data.extend(&vin.sequence.to_le_bytes());
    }

    serialized_data.extend(&get_compact_size(transaction.vout.len()));
    // Serialize the outputs
    for vout in &transaction.vout {
        // Serialize the value
        serialized_data.extend(&vout.value.to_le_bytes());

        // Serialize the scriptpubkey
        let scriptpubkey = hex::decode(&vout.scriptpubkey).unwrap();
        serialized_data.extend(&get_compact_size(scriptpubkey.len()));
        serialized_data.extend(&scriptpubkey);
    }
    serialized_data.extend(&transaction.locktime.to_le_bytes());
    let txid = double_sha256(&serialized_data);
    txid
}

pub fn create_block_header(merkle_root: Vec<u8>) -> Vec<u8> {
    let mut blockheader: Vec<u8> = Vec::new();
    // 0x20000000
    blockheader.push(0x20);
    blockheader.push(0x00);
    blockheader.push(0x00);
    blockheader.push(0x00);

    for _ in 0..32 {
        blockheader.push(0x00)
    }

    blockheader.extend(merkle_root);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Failed to get Unix timestamp")
        .as_secs() as u32;
    blockheader.extend_from_slice(&timestamp.to_le_bytes());

    // Compact representation of the target
    let target = "1f00ffff".to_string();
    let mut compact_target = decode(target).unwrap();
    compact_target.reverse();
    blockheader.extend(&compact_target);
    // print_hex_string(&blockheader);
    blockheader
}

pub fn calculate_merkle_root(tx_ids: &[Vec<u8>]) -> Vec<u8> {
    let mut leaves: Vec<Vec<u8>> = tx_ids.to_vec();

    while leaves.len() > 1 {
        let mut new_leaves = Vec::with_capacity(leaves.len() / 2 + leaves.len() % 2);

        for chunks in leaves.chunks(2) {
            let mut combined = Vec::new();

            if chunks.len() == 2 {
                // Handle the case when there are two leaves in the chunk
                for chunk in chunks {
                    combined.extend(chunk.iter());
                }
            } else {
                // Handle the case when there is only one leaf in the chunk
                let chunk = &chunks[0];
                combined.extend(chunk.iter());
                combined.extend(chunk.iter());
            }
            // print_hex_string(&combined);
            let double_sha256 = double_sha256(&combined);
            new_leaves.push(double_sha256);
        }

        leaves = new_leaves;
    }

    let merel = leaves.pop().unwrap();
    // merel.reverse();
    merel
}

pub fn mine_block(block_header: &Vec<u8>) -> (Vec<u8>, u32) {
    let mut nonce: u32 = 0;
    loop {
        let mut block_data = block_header.to_vec();
        block_data.extend_from_slice(&nonce.to_le_bytes());

        let mut double_hash = double_sha256(&block_data);
        double_hash.reverse();
        if double_hash.as_slice() < &DIFFICULTY_TARGET[..] {
            return (block_data, nonce);
        }

        nonce += 1;
    }
}

pub fn print_soln(block_header: &Vec<u8>, trx: &Vec<u8>, txids: &Vec<Vec<u8>>) {
    // Get the current directory
    let current_dir = std::env::current_dir().expect("Failed to get current directory");

    // Navigate to the parent directory
    let parent_dir = current_dir
        .parent()
        .expect("Failed to get parent directory");

    // Create the file path
    let file_path = parent_dir.join("output.txt");

    // Create the file and write to it
    let mut file = File::create(&file_path).expect("Failed to create file");

    // Write the block header
    // file.write_all(b"Block Header: ").expect("Failed to write block header");
    file.write_all(&hex::encode(block_header).as_bytes())
        .expect("Failed to write block header");
    file.write_all(b"\n").expect("Failed to write newline");

    file.write_all(&hex::encode(trx).as_bytes())
        .expect("Failed to write block header");
    file.write_all(b"\n").expect("Failed to write newline");

    // Write the transaction IDs
    // file.write_all(b"Transaction IDs:\n").expect("Failed to write transaction IDs header");
    for txid in txids {
        let mut revtrx = txid.to_vec();
        revtrx.reverse();
        file.write_all(&hex::encode(revtrx).as_bytes())
            .expect("Failed to write transaction ID");
        file.write_all(b"\n").expect("Failed to write newline");
    }

    // println!("File written: {:?}", file_path);
}

pub fn calculate_wtxid(transactions: Vec<Vec<u8>>) -> Vec<u8> {
    let mut wtxids: Vec<Vec<u8>> = Vec::new();
    wtxids
        .push(decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap());
    for txn in transactions.iter().rev() {
        wtxids.push(double_sha256(&txn));
    }
    let wtx_merkle_root = calculate_merkle_root(&wtxids);
    wtx_merkle_root
}


pub fn populate(trxns: &Vec<GasedTransaction>) -> (Vec<Vec<u8>>,Vec<Vec<u8>>)
{
    let mut a: Vec<Vec<u8>> = Vec::new();
    let mut b: Vec<Vec<u8>> = Vec::new();
    let mut cum_weight = 0;
    for trxn in trxns.iter()
    {
        a.push(trxn.data.clone());
        b.push(trxn.txid.clone());
        // println!("weight {} weight so far{}",trxn.weight,cum_weight);
        cum_weight += trxn.weight;
        if cum_weight > 4000000 {
            a.pop();
            b.pop();
            break;
        }
    }
    (a,b)
}