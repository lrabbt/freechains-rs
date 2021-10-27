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
    let chain_pubkey1 = "";
    let chain_pubkey2 = "";
    client.join_chain(&chain_id, &[chain_pubkey1, chain_pubkey2])?;

    // Generate public and private keys
    let (pubkey, pvtkey) = client.crypto_pubpvt("strong_password")?;

    let mut chain_client = client.chain(&chain_id);

    // Post on public chain
    chain_client.post(Some(&pvtkey), false, b"Hello, forum!")?;
    Ok(())
}
```

## Roadmap

### Publication

* [ ] Publish on [crates.io](http://crates.io)

### Commands

| STATUS   | COMMAND                                                   |
|----------|-----------------------------------------------------------|
| DONE     | `crypto pubprv $pwd`                                      |
| DONE     | `crypto share $pwd`                                       |
| DONE     | `peer $remote ping`                                       |
| DONE     | `peer $remote chains`                                     |
| DONE     | `peer $remote send $chain`                                |
| DONE     | `peer $remote recv $chain`                                |
| DONE     | `chains list`                                             |
| DONE     | `chains leave $chain`                                     |
| DONE     | `chains join $chain $keys[@]`                             |
| DONE     | `chains join $chain`                                      |
| **TODO** | `chains listen`                                           |
| DONE     | `chain $chain like $lk ${cmds[3]} ${opts["--sign"]} $len` |
| DONE     | `chain $chain genesis`                                    |
| DONE     | `chain $chain heads [blocked]`                            |
| DONE     | `chain $chain get block $hash $decrypt (?)`               |
| DONE     | `chain $chain get payload $hash $decrypt (?)`             |
| DONE     | `chain $chain post $sign $encrypt ${pay.size}`            |
| DONE     | `chain $chain traverse $downto`                           |
| DONE     | `chain $chain reps ${cmds[3]}`                            |
| **TODO** | `chain $chain listen`                                     |


## License

MIT
