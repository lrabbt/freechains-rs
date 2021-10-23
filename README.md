# freechains-rs

A [Freechains](https://github.com/Freechains) client rust library.

## Objective

`freechains-rs` is intended as a simple Freechains client interface for rust development.

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
