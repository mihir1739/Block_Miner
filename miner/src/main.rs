use miner::structs::{GasedTransaction, Transaction};
use miner::utils::print_hex_string;
use miner::{
    calculate_merkle_root, calculate_wtxid, create_block_header, create_coinbase_trx, get_compact_size, mine_block, populate, print_soln
};
use std::error::Error;
use std::fs::read_dir;
fn main() -> Result<(), Box<dyn Error>> {
    let directory_path = "../mempool";
    // let mut txids: Vec<Vec<u8>> = Vec::new();
    // let mut transactions: Vec<Vec<u8>> = Vec::new();
    let mut transactions:Vec<GasedTransaction> = Vec::new();
    // transactions.extend(&crx);
    // txids.push(crx);
    for entry in read_dir(directory_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.extension().unwrap() == "json" {
            let transaction = Transaction::parse_from_file(path.to_str().unwrap())?;

            // println!("--- Parsed file: {}", path.display());
            let isegwit = transaction.valid_trans();
            if isegwit.0 {
                let serialized_data = transaction.get_data(isegwit.1);
                // let weight = calculate_tx_weight(&serialized_data);
                // println!(
                //     "Transaction {:?} Gas {} Weight{}",
                //     transaction,
                //     transaction.calculate_gas(),
                //     weight
                // );

                // print!("Hashed Data ");
                // print_hex_string(&serialized_data);
                transactions.push(GasedTransaction{gas:transaction.calculate_gas(),weight:transaction.calculate_tx_weight(),data:serialized_data,txid: transaction.get_txid(),is_segwit: isegwit.1 });
                // print!("Transaction Id ");
                // let txis = transaction.get_txid();

                // transactions.extend(&txis);
                // print_hex_string(&txis);
                // txids.push(txis);
            }
        }
    }
    transactions.sort_by(|a, b| b.cmp(a));
    let (trans,mut txids) = populate(&transactions);
    let wtxid_merkle = calculate_wtxid(trans);
    let (trx, crx) = create_coinbase_trx(wtxid_merkle);
    txids.push(crx);
    txids.reverse();
    let merkle_root = calculate_merkle_root(&txids);
    let block_header = create_block_header(merkle_root);
    let (block, _nonce) = mine_block(&block_header);
    // print_hex_string(&block);
    print_soln(&block, &trx, &txids);
    Ok(())
}
