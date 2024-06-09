use crate::utils::get_current_unix_timestamp_u32;
use crate::{calculate_txid, get_compact_size, serialize_transation, validate_transaction};
use serde::Deserialize;
use serde_json::from_reader;
use std::cmp::Ordering;
use std::fs::File;
// Defining the structs
#[derive(Debug, Deserialize)]
pub struct Prevout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: String,
    pub value: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Witness(pub Vec<String>);

#[derive(Debug, Deserialize)]
pub struct Vin {
    pub txid: String,
    pub vout: u32,
    pub prevout: Prevout,
    pub scriptsig: String,
    pub scriptsig_asm: String,
    pub witness: Option<Witness>,
    pub is_coinbase: bool,
    pub sequence: u32,
}

#[derive(Debug, Deserialize)]
pub struct Vout {
    pub scriptpubkey: String,
    pub scriptpubkey_asm: String,
    pub scriptpubkey_type: String,
    pub scriptpubkey_address: Option<String>,
    pub value: u32,
}
#[derive(Debug, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub locktime: u32,
    pub vin: Vec<Vin>,
    pub vout: Vec<Vout>,
}

#[derive(Debug, Deserialize, Eq)]
pub struct GasedTransaction {
    pub gas: u32,
    pub weight: u32,
    pub data: Vec<u8>,
    pub txid: Vec<u8>,
    pub is_segwit: bool,
}

impl Transaction {
    pub fn parse_from_file(file_path: &str) -> Result<Transaction, std::io::Error> {
        let file = File::open(file_path)?;
        let transaction: Transaction = from_reader(file)?;
        Ok(transaction)
    }

    /// validates a transaction
    ///
    /// # Arguments
    ///
    /// * `self`: a `Transaction` object
    ///
    /// # Returns
    ///
    /// 'bool' the transaction is valid or not
    pub fn valid_trans(&self) -> (bool, bool) {
        // Preliminary test to find the total input > total output
        let gas = self.calculate_gas();
        // println!("Input {}, Output {}, Gas {}", input, output, input - output);
        if gas <= 0 {
            return (false, false);
        }
        if self.locktime != 0 {
            if self.locktime < 499999999 {
                return (false, false);
            } else {
                let unixtime = get_current_unix_timestamp_u32();
                if self.locktime > unixtime {
                    return (false, false);
                }
            }
        }
        match validate_transaction(self) {
            Ok(flag) => return (true, flag),
            Err(_err) => {
                // println!("Encountered error {}",err);
                return (false, false);
            }
        }
    }
    pub fn get_data(&self, issegwit: bool) -> Vec<u8> {
        return serialize_transation(self, issegwit);
    }
    pub fn get_txid(&self) -> Vec<u8> {
        return calculate_txid(self);
    }

    pub fn calculate_gas(&self) -> u32 {
        let mut input:u32 = 0;
        let mut output:u32 = 0;
        for vin in self.vin.iter() {
            input += vin.prevout.value;
        }
        for vout in self.vout.iter() {
            output += vout.value;
        }
        input - output
    }

    pub fn calculate_tx_weight(&self) -> u32 {
        // println!("------------------------------------------------------------------------------------------------");
        let mut base_size = 4; // Version
        base_size += get_compact_size(self.vin.len()).len(); // Input count
        base_size += get_compact_size(self.vout.len()).len(); // Output count
        base_size += 4; // Locktime
        // print!("{} ",base_size);

        let mut witness_size = 0;

        for vin in &self.vin {
            base_size += 32; // Previous TXID
            base_size += 4; // Previous output index
            base_size += get_compact_size(vin.scriptsig.len() / 2).len(); // ScriptSig length
            base_size += vin.scriptsig.len() / 2; // ScriptSig
            base_size += 4; // Sequence

            if let Some(witness) = &vin.witness {
                witness_size += 2; // Witness count
                witness_size += get_compact_size(witness.0.len()).len(); // Witness element count
                for element in &witness.0 {
                    witness_size += get_compact_size(element.len() / 2).len(); // Witness element length
                    witness_size += element.len() / 2 // Witness element
                }
            }
        }
        // print!("{} ",base_size);
        for vout in &self.vout {
            base_size += 8; // Value
            base_size += get_compact_size(vout.scriptpubkey.len() / 2).len(); // ScriptPubKey length
            base_size += vout.scriptpubkey.len() / 2; // ScriptPubKey
        }
        // print!("{} ",base_size);
        let weight = 4 * base_size + witness_size;
        // print!("{}\n",weight);
        weight as u32
    }
}

// Implement the Eq trait for Transaction
impl PartialEq for GasedTransaction {
    fn eq(&self, other: &Self) -> bool {
        self.gas == other.gas && self.weight == other.weight
    }
}

// Implement the Ord trait for Transaction
impl Ord for GasedTransaction {
    fn cmp(&self, other: &Self) -> Ordering {
        // Compare gas in descending order
        if self.gas/self.weight > other.gas/other.weight {
            return Ordering::Greater;
        } else if self.gas/self.weight < other.gas/other.weight {
            return Ordering::Less;
        }
        // If gas is equal, compare weight in ascending order
        if self.weight < other.weight {
            return Ordering::Less;
        } else if self.weight > other.weight {
            return Ordering::Greater;
        }

        // If both gas and weight are equal, consider them equal
        Ordering::Equal
    }
}

// Implement the PartialOrd trait for Transaction
impl PartialOrd for GasedTransaction {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
