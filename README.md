# freechains-rs

A [Freechains](https://github.com/Freechains) client rust library.

## Objective

`freechains-rs` is intended as a simple Freechains client interface for rust development.

## Usage

List all server chains.

```rust
use freechains::{Client, ClientError};

fn main() -> Result<(), ClientError> {
    let mut client = Client::new("0.0.0.0:8330");
    let chain_ids = client.chains()?;
    Ok(())
}
```

Join and post on a public chain.

```rust
use freechains::{Client, ChainId, ClientError};

fn main() -> Result<(), ClientError> {
    let mut client = Client::new("0.0.0.0:8330");

    // Join public chain
    let chain_id = ChainId::new("#forum")?;
    let chain_pubkey1 = "some_known_key1";
    let chain_pubkey2 = "some_known_key2";
    client.join_chain(&chain_id, &[chain_pubkey1, chain_pubkey2])?;

    // Generate public and private keys
    let (pubkey, pvtkey) = client.crypto_pubpvt("strong_password")?;

    let mut chain_client = client.chain(&chain_id);

    // Post on public chain
    chain_client.post(Some(&pvtkey), false, b"Hello, forum!")?;
    Ok(())
}
```

## License

MIT
