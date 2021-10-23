//! The `freechains` module implements freechains client utilities.
//!
//! # Roadmap
//!
//! | STATUS   | COMMAND                                                   |
//! |----------|-----------------------------------------------------------|
//! | DONE     | `crypto pubprv $pwd`                                      |
//! | DONE     | `crypto share $pwd`                                       |
//! | DONE     | `peer $remote ping`                                       |
//! | DONE     | `peer $remote chains`                                     |
//! | DONE     | `peer $remote send $chain`                                |
//! | DONE     | `peer $remote recv $chain`                                |
//! | DONE     | `chains list`                                             |
//! | DONE     | `chains leave $chain`                                     |
//! | DONE     | `chains join $chain $keys[@]`                             |
//! | DONE     | `chains join $chain`                                      |
//! | **TODO** | `chains listen`                                           |
//! | DONE     | `chain $chain like $lk ${cmds[3]} ${opts["--sign"]} $len` |
//! | DONE     | `chain $chain genesis`                                    |
//! | DONE     | `chain $chain heads [blocked]`                            |
//! | DONE     | `chain $chain get block $hash $decrypt (?)`               |
//! | DONE     | `chain $chain get payload $hash $decrypt (?)`             |
//! | DONE     | `chain $chain post $sign $encrypt ${pay.size}`            |
//! | DONE     | `chain $chain traverse $downto`                           |
//! | DONE     | `chain $chain reps ${cmds[3]}`                            |
//! | **TODO** | `chain $chain listen`                                     |

#![warn(missing_docs)]

use serde::Deserialize;

use std::convert::TryFrom;
use std::error::Error;
use std::fmt;
use std::io::prelude::*;
use std::io::{self, BufReader};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::num;

/// Freechains host version supported.
pub const HOST_VERSION: (u8, u8, u8) = (0, 8, 6);

/// Freechains client.
///
/// # Examples
///
/// List all server chains.
///
/// ```no_run
/// use freechains::{Client, ClientError};
///
/// # fn main() -> Result<(), ClientError> {
/// let mut client = Client::connect("0.0.0.0:8300")?;
/// let chain_ids = client.chains()?;
///
/// # Ok(())
/// # }
/// ```
pub struct Client {
    stream: TcpStream,
}

impl Client {
    /// Creates a [Client], which connects to freechains server.
    pub fn connect(addrs: impl ToSocketAddrs) -> io::Result<Client> {
        let stream = TcpStream::connect(addrs)?;

        Ok(Client { stream })
    }

    fn write_message(&mut self, msg: &str) -> io::Result<()> {
        let preamble = format!(
            "FC v{}.{}.{}",
            HOST_VERSION.0, HOST_VERSION.1, HOST_VERSION.2
        );
        writeln!(self.stream, "{} {}", preamble, msg)
    }

    fn read_message(&self) -> Result<String, ClientError> {
        let response = BufReader::new(&self.stream)
            .lines()
            .next()
            .ok_or(ClientError::EmptyResponseError)??;

        let mut chars = response.chars();

        let first_char = chars.next();
        if let Some(c) = first_char {
            if c == '!' {
                chars.next();
                return Err(ClientError::ExecutionError(chars.collect()));
            }
        }

        Ok(String::from(response))
    }

    /// Requests freechains server for a symmetric encryption for password `pwd`.
    pub fn crypto_shared(&mut self, pwd: &str) -> Result<String, ClientError> {
        self.write_message(&format!("crypto shared {}", pwd))?;

        self.read_message()
    }

    /// Requests freechains server to generate public and private key with password `pwd`.
    pub fn crypto_pubpvt(&mut self, pwd: &str) -> Result<(String, String), ClientError> {
        let msg = format!("crypto shared {}", pwd);
        self.write_message(&msg)?;

        let line = self.read_message()?;

        let mut split_line = line.split(" ");
        let pubkey = String::from(split_line.next().ok_or(ClientError::ExecutionError(
            String::from("missing public key"),
        ))?);
        let prvkey = String::from(split_line.next().ok_or(ClientError::ExecutionError(
            String::from("missing private key"),
        ))?);

        Ok((pubkey, prvkey))
    }

    /// Requests freechains server for a list of subscribed chains.
    pub fn chains(&mut self) -> Result<ChainsIds, ClientError> {
        self.write_message("chains list")?;

        let line = self.read_message()?;
        let chains: Result<Vec<_>, _> = line.split(' ').map(ChainId::new).collect();
        let chains = chains?;

        Ok(chains)
    }

    /// Requests freechains server to join private chain with creators defined by keys. Chain name
    /// must start with "$".
    ///
    /// Returns created chain hash.
    pub fn join_chain(&mut self, chain: &ChainId, keys: &[&str]) -> Result<String, ClientError> {
        let msg = format!("chains join {} {}", chain, keys.join(" "));
        self.write_message(&msg)?;

        let hash = self.read_message()?;

        Ok(hash)
    }

    /// Gets freechains chain client.
    pub fn chain(&mut self, chain: &ChainId) -> ChainClient {
        ChainClient::new(self, &chain.to_string())
    }

    /// Gets freechains peer client.
    pub fn peer(&mut self, peer: impl ToSocketAddrs) -> io::Result<PeerClient> {
        PeerClient::new(self, peer)
    }
}

/// Freechains chain client actions. Must be created from [Client].
///
/// # Examples
///
/// Opens '$chat' chain client and gets it's genesis block hash.
///
/// ```no_run
/// # use freechains::{Client, ChainId, ClientError};
///
/// # fn main() -> Result<(), ClientError> {
/// let mut client = Client::connect("0.0.0.0:8300")?;
/// let chain_id = ChainId::new("$chat")?;
///
/// let mut client = client.chain(&chain_id);
/// let genesis_hash = client.genesis();
///
/// # Ok(())
/// # }
/// ```
pub struct ChainClient<'a> {
    client: &'a mut Client,
    name: String,
}

impl<'a> ChainClient<'a> {
    fn new(client: &'a mut Client, name: &str) -> ChainClient<'a> {
        let name = String::from(name);
        ChainClient { client, name }
    }

    fn write_message(&mut self, msg: &str) -> io::Result<()> {
        let msg = format!("chain {}", msg);
        self.client.write_message(&msg)
    }

    fn read_message(&self) -> Result<String, ClientError> {
        let response = self.client.read_message();
        response
    }

    /// Returns chain name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Requests freechains server to leave chain.
    pub fn leave(self) -> Result<bool, ClientError> {
        let msg = format!("chains leave {}", self.name);
        self.client.write_message(&msg)?;

        Ok(self.read_message()? == "true")
    }

    /// Requests freechains for the hash of genesis.
    pub fn genesis(&mut self) -> Result<String, ClientError> {
        self.write_message("genesis")?;

        let response = self.read_message()?;
        Ok(response)
    }

    /// Requests freechains server for a payload for the specified post. Post must be identified by
    /// its hash.
    pub fn payload(&mut self, hash: &str, pvtkey: Option<&str>) -> Result<Vec<u8>, ClientError> {
        let pvtkey = pvtkey.unwrap_or("null");
        let msg = format!("get payload {} {}", hash, pvtkey);
        self.write_message(&msg)?;

        let payload_size = self.read_message()?.parse()?;

        let mut buf = [0, payload_size];
        self.client.stream.read_exact(&mut buf)?;

        Ok(buf.to_vec())
    }

    /// Requests freechains server for a block of content. Content must be identified by its hash.
    pub fn content(
        &mut self,
        hash: &str,
        pvtkey: Option<&str>,
    ) -> Result<ContentBlock, ClientError> {
        let pvtkey = pvtkey.unwrap_or("null");
        let msg = format!("get block {} {}", hash, pvtkey);
        self.write_message(&msg)?;

        let block_size = self.read_message()?.parse()?;

        let mut buf = [0, block_size];
        self.client.stream.read_exact(&mut buf)?;

        let content: ContentBlock = serde_json::from_slice(&buf)?;

        Ok(content)
    }

    /// Requests freechains server to post a message.
    pub fn post(
        &mut self,
        signature: Option<&str>,
        encrypt: bool,
        payload: &[u8],
    ) -> Result<String, ClientError> {
        let signature = signature.unwrap_or("anon");
        let msg = format!("post {} {} {}", signature, encrypt, payload.len());
        self.write_message(&msg)?;

        self.client.stream.write_all(payload)?;

        self.read_message()
    }

    /// Requests freechains server to get chain heads.
    pub fn heads(&mut self, blocked: bool) -> Result<Vec<String>, ClientError> {
        let mut msg = String::from("heads");
        if blocked {
            msg = format!("{} blocked", msg);
        }
        self.write_message(&msg)?;

        let response = self.read_message()?;
        let hashes = response.split(' ').map(String::from).collect();

        Ok(hashes)
    }

    /// Requests freechains server to traverse all messages hashes starting with required messages
    /// hashes.
    pub fn traverse(&mut self, up_blocks: &[&str]) -> Result<Vec<String>, ClientError> {
        let msg = format!("traverse {}", up_blocks.join(" "));
        self.write_message(&msg)?;

        let response = self.read_message()?;
        let hashes = response.split(' ').map(String::from).collect();

        Ok(hashes)
    }

    /// Requests freechains server for content reputation.
    pub fn reputation(&mut self, hash: &str) -> Result<usize, ClientError> {
        let msg = format!("reps {}", hash);
        self.write_message(&msg)?;

        let response = self.read_message()?;
        let reputation = response.parse()?;

        Ok(reputation)
    }

    /// Requests freechains server to give content a like.
    pub fn like(&mut self, hash: &str, pvtkey: &str, reason: &[u8]) -> Result<String, ClientError> {
        let msg = format!("like 1 {} {} {}", hash, pvtkey, reason.len());
        self.write_message(&msg)?;
        self.client.stream.write_all(reason)?;

        let hash = self.read_message()?;

        Ok(hash)
    }

    /// Requests freechains server to give content a dislike.
    pub fn dislike(
        &mut self,
        hash: &str,
        pvtkey: &str,
        reason: &[u8],
    ) -> Result<String, ClientError> {
        let msg = format!("like -1 {} {} {}", hash, pvtkey, reason.len());
        self.write_message(&msg)?;
        self.client.stream.write_all(reason)?;

        let hash = self.read_message()?;

        Ok(hash)
    }
}

impl fmt::Display for ChainClient<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.name.fmt(f)
    }
}

impl fmt::Debug for ChainClient<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.name.fmt(f)
    }
}

/// Freechains peer client actions. Must be created from [Client].
///
/// # Examples
///
/// Opens peer client from local server `host1:8330` to remote server `host2:8330` and lists it's chains.
///
/// ```no_run
/// use freechains::{Client, ClientError};
///
/// # fn main() -> Result<(), ClientError> {
/// let mut client = Client::connect("host1:8330")?;
/// let mut client = client.peer("host2:8330")?;
/// let chains = client.chains()?;
///
/// # Ok(())
/// # }
/// ```
pub struct PeerClient<'a> {
    client: &'a mut Client,
    peer: SocketAddr,
}

impl<'a> PeerClient<'a> {
    fn new(client: &'a mut Client, peer: impl ToSocketAddrs) -> io::Result<PeerClient<'a>> {
        let mut peer = peer.to_socket_addrs()?;
        let peer = peer.next().unwrap_or("0.0.0.0:8330".parse().unwrap());

        Ok(PeerClient { client, peer })
    }

    fn write_message(&mut self, msg: &str) -> io::Result<()> {
        let msg = format!("peer {}:{} {}", self.peer.ip(), self.peer.port(), msg);
        self.client.write_message(&msg)
    }

    /// Requests freechains server to send chain to other freechains peer.
    pub fn send_chain(&mut self, id: &ChainId) -> Result<(), ClientError> {
        let msg = format!("send {}", id);
        self.write_message(&msg)?;

        self.client.read_message()?;

        Ok(())
    }

    /// Requests freechains server to receive chain from other freechains peer.
    pub fn receive_chain(&mut self, id: &ChainId) -> Result<(), ClientError> {
        let msg = format!("recv {}", id);
        self.write_message(&msg)?;

        self.client.read_message()?;

        Ok(())
    }

    /// Requests freechains server to ping other freechains peer.
    pub fn ping(&mut self) -> Result<(), ClientError> {
        self.write_message("ping")?;
        self.client.read_message()?;
        Ok(())
    }

    /// Requests freechains server to request other freechains peer for their chains.
    pub fn chains(&mut self) -> Result<ChainsIds, ClientError> {
        self.write_message("chains")?;

        let response = self.client.read_message()?;
        let chains: Result<Vec<_>, _> = response.split(' ').map(ChainId::new).collect();
        let chains = chains?;

        Ok(chains)
    }
}

/// Type of freechains chain.
#[derive(Debug, PartialEq, Eq)]
pub enum ChainType {
    /// Private chain. Identifier starts with `$`.
    PrivateChain,

    /// Public chain. Identifier starts with `#`.
    PublicChain,

    /// Public Identity chain. Identifier starts with `@`.
    PublicIdentityChain,
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let c: char = self.into();
        write!(f, "{}", c)
    }
}

impl TryFrom<char> for ChainType {
    type Error = InvalidChainNameError;

    fn try_from(c: char) -> Result<Self, Self::Error> {
        match c {
            '$' => Ok(ChainType::PrivateChain),
            '#' => Ok(ChainType::PublicChain),
            '@' => Ok(ChainType::PublicIdentityChain),
            _ => Err(InvalidChainNameError),
        }
    }
}

impl From<&ChainType> for char {
    fn from(t: &ChainType) -> char {
        match t {
            ChainType::PrivateChain => '$',
            ChainType::PublicChain => '#',
            ChainType::PublicIdentityChain => '@',
        }
    }
}

type ChainsIds = Vec<ChainId>;

/// Freechains chain identifier. Contains its type and name.
#[derive(Debug, PartialEq, Eq)]
pub struct ChainId {
    chain_type: ChainType,
    name: String,
}

impl ChainId {
    /// Creates new [ChainId] from [&str].
    pub fn new(name: &str) -> Result<ChainId, InvalidChainNameError> {
        let mut chars = name.chars();
        let first_char = chars.next();
        let first_char = first_char.ok_or(InvalidChainNameError)?;

        let chain_type = ChainType::try_from(first_char)?;
        let name = chars.collect();

        Ok(ChainId { chain_type, name })
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.chain_type, self.name)
    }
}

impl std::str::FromStr for ChainId {
    type Err = InvalidChainNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ChainId::new(s)
    }
}

/// Representation of freechains content block response. It is created from [content](ChainClient::content).
#[derive(Deserialize)]
pub struct ContentBlock {
    /// Content hash.
    pub hash: String,
    /// Content instant of creation. Milliseconds since [std::time::UNIX_EPOCH].
    pub time: usize,
    /// Content payload information.
    pub payload: Option<PayloadBlock>,
    /// If content is a like, like information is stored here.
    pub like: Option<LikeBlock>,
    /// Content signature information.
    pub signature: Option<SignatureBlock>,
    /// Blocks which points to this content block.
    pub backs: Vec<String>,
}

/// Representation of freechains payload field from content block response [ContentBlock].
#[derive(Deserialize)]
pub struct PayloadBlock {
    /// Payload hash.
    pub hash: String,
    /// If payload is encrypted.
    pub crypt: bool,
}

/// Representation of freechains like field from content block response [ContentBlock].
#[derive(Deserialize)]
pub struct LikeBlock {
    /// Like hash.
    pub hash: String,
    /// Defines if is a like or a dislike. `1` is a like, `-1` is a dislike.
    pub n: usize,
}

/// Representation of freechains signature field from content block response [ContentBlock].
#[derive(Deserialize)]
pub struct SignatureBlock {
    /// Signature hash.
    pub hash: String,
    /// Signature public key.
    pub pubkey: String,
}

/// Error returned when dealing with client-server actions.
#[derive(Debug)]
pub enum ClientError {
    /// Server responded with empty message.
    EmptyResponseError,

    /// Server responded with execution error. Any server response starting with `!` is reported as
    /// an [ExecutionError](ClientError::ExecutionError).
    ExecutionError(String),

    /// This may only happen if freechains server version is different.
    InvalidServerResponseError(String),

    /// Error on communication channel.
    IoError(io::Error),
}

impl Error for ClientError {}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClientError::EmptyResponseError => write!(f, "empty response"),
            ClientError::ExecutionError(e) => write!(f, "execution error: {}", e),
            ClientError::InvalidServerResponseError(e) => {
                write!(f, "invalid server response: {}", e)
            }
            ClientError::IoError(e) => e.fmt(f),
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(error: io::Error) -> Self {
        ClientError::IoError(error)
    }
}

impl From<num::ParseIntError> for ClientError {
    fn from(error: num::ParseIntError) -> Self {
        ClientError::ExecutionError(error.to_string())
    }
}

impl From<serde_json::Error> for ClientError {
    fn from(error: serde_json::Error) -> Self {
        ClientError::InvalidServerResponseError(error.to_string())
    }
}

impl From<InvalidChainNameError> for ClientError {
    fn from(error: InvalidChainNameError) -> Self {
        ClientError::InvalidServerResponseError(error.to_string())
    }
}

/// Error returned when a chain is created with invalid name.
#[derive(Debug)]
pub struct InvalidChainNameError;

impl Error for InvalidChainNameError {}

impl fmt::Display for InvalidChainNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "chain name must start with '$', '@' or '#'")
    }
}
