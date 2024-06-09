# Bitcoin Mining Simulation

This project simulates the process of mining a Bitcoin block by taking transactions from a mempool, verifying them, and creating a valid block header and coinbase transaction. The project is written in Rust and demonstrates various aspects of Bitcoin mining, including transaction validation, Merkle root calculation, and proof-of-work mining.

## Features

- **Transaction Parsing**: The project reads transaction data from JSON files in a specified directory (`../mempool`). It parses the transactions and performs validation checks.
- **Transaction Validation**: Transactions are validated using the `validate_transaction` function, which supports various script types, including P2PKH (Pay-to-Public-Key-Hash) and P2WPKH (Pay-to-Witness-Public-Key-Hash).
- **Transaction Weight Calculation**: The weight of each transaction is calculated using the `calculate_tx_weight` function, which follows the Bitcoin weight calculation rules.
- **Merkle Root Calculation**: The project calculates the Merkle root of the transactions using the `calculate_merkle_root` function, following the Merkle tree construction rules.
- **Coinbase Transaction Generation**: A coinbase transaction is generated using the `create_coinbase_trx` function, which includes the Witness Merkle root as part of the coinbase transaction data.
- **Block Header Construction**: The project constructs a block header using the `create_block_header` function, which includes the calculated Merkle root and other necessary block header fields.
- **Proof-of-Work Mining**: The project performs proof-of-work mining using the `mine_block` function, which iterates over nonce values until a valid block header hash is found that satisfies the target difficulty.
- **Output Generation**: The final block header, coinbase transaction, and transaction IDs are written to an `output.txt` file using the `print_soln` function.

## Usage

1. Clone the repository or download the source code.
2. Place your transaction JSON files in the `../mempool` directory.
3. Build and run the project using Cargo:
```cargo
cargo run
```

4. The output, including the block header, coinbase transaction, and transaction IDs, will be written to the `output.txt` file in the parent directory.

## Dependencies

This project uses the following Rust crates:

- `hex`: For encoding and decoding hexadecimal strings
- `secp256k1`: For ECDSA signature verification
- `sha2`: For SHA-256 hashing
- `serde`: For deserializing transaction data from JSON files
- `serde_json`: For deserializing transaction data from JSON files

## Contributing

Contributions to this project are welcome. If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

## License

This project is licensed under the [MIT License](LICENSE).