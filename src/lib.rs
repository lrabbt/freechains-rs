//! The `freechains` module implements freechains client utilities.
//!
//! Main use comes from [Client] struct.
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
/// Due to freechains server limitations, a new TCP connection is opened for each client request.
///
/// # Examples
///
/// List all server chains.
///
/// ```no_run
/// use freechains::{Client, ClientError};
///
/// # fn main() -> Result<(), ClientError> {
/// let mut client = Client::new("0.0.0.0:8300")?;
/// let chain_ids = client.chains()?;
///
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Client {
    addr: SocketAddr,
}

impl Client {
    /// Creates a freechains client.
    pub fn new(addrs: impl ToSocketAddrs) -> io::Result<Client> {
        let mut addr = addrs.to_socket_addrs()?;
        let addr = addr
            .next()
            .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 8330)));

        Ok(Client { addr })
    }

    fn preamble(&self) -> String {
        format!(
            "FC v{}.{}.{}",
            HOST_VERSION.0, HOST_VERSION.1, HOST_VERSION.2
        )
    }

    fn read_message(stream: impl Read) -> Result<String, ClientError> {
        let response = BufReader::new(stream)
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
        let mut stream = TcpStream::connect(self.addr)?;

        writeln!(stream, "{} crypto shared", self.preamble())?;
        writeln!(stream, "{}", pwd)?;

        Client::read_message(&stream)
    }

    /// Requests freechains server to generate public and private key with password `pwd`.
    pub fn crypto_pubpvt(&mut self, pwd: &str) -> Result<(String, String), ClientError> {
        let mut stream = TcpStream::connect(self.addr)?;

        writeln!(stream, "{} crypto pubpvt", self.preamble())?;
        writeln!(stream, "{}", pwd)?;

        let line = Client::read_message(&stream)?;

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
        let mut stream = TcpStream::connect(self.addr)?;

        writeln!(stream, "{} chains list", self.preamble())?;

        let line = Client::read_message(&stream)?;
        let chains: Result<Vec<_>, _> = line.split(' ').map(ChainId::new).collect();
        let chains = chains?;

        Ok(chains)
    }

    /// Requests freechains server to join private chain with creators defined by keys. Chain name
    /// must start with "$".
    ///
    /// Returns created chain hash.
    pub fn join_chain(&mut self, chain: &ChainId, keys: &[&str]) -> Result<String, ClientError> {
        let mut stream = TcpStream::connect(self.addr)?;

        writeln!(
            stream,
            "{} chains join {} {}",
            self.preamble(),
            chain,
            keys.join(" ")
        )?;

        let hash = Client::read_message(&stream)?;

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
/// let mut client = Client::new("0.0.0.0:8300")?;
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

    fn preamble(&self) -> String {
        format!("{} chain {}", self.client.preamble(), self.name)
    }

    fn read_message(stream: &TcpStream) -> Result<String, ClientError> {
        Client::read_message(stream)
    }

    /// Returns chain name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Requests freechains server to leave chain.
    pub fn leave(self) -> Result<bool, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(
            stream,
            "{} chains leave {}",
            self.client.preamble(),
            self.name
        )?;

        Ok(Client::read_message(&stream)? == "true")
    }

    /// Requests freechains for the hash of genesis.
    pub fn genesis(&mut self) -> Result<String, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(stream, "{} genesis", self.preamble())?;

        let response = ChainClient::read_message(&stream)?;
        Ok(response)
    }

    /// Requests freechains server for a payload for the specified post. Post must be identified by
    /// its hash.
    pub fn payload(&mut self, hash: &str, pvtkey: Option<&str>) -> Result<Vec<u8>, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        let pvtkey = pvtkey.unwrap_or("null");
        writeln!(
            stream,
            "{} get payload {} {}",
            self.preamble(),
            hash,
            pvtkey
        )?;

        let payload_size = ChainClient::read_message(&stream)?.parse()?;

        let mut buf = [0, payload_size];
        stream.read_exact(&mut buf)?;

        Ok(buf.to_vec())
    }

    /// Requests freechains server for a block of content. Content must be identified by its hash.
    pub fn content(
        &mut self,
        hash: &str,
        pvtkey: Option<&str>,
    ) -> Result<ContentBlock, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        let pvtkey = pvtkey.unwrap_or("null");
        writeln!(stream, "{} get block {} {}", self.preamble(), hash, pvtkey)?;

        let block_size = ChainClient::read_message(&stream)?.parse()?;

        let mut buf = [0, block_size];
        stream.read_exact(&mut buf)?;

        let content: ContentBlock = serde_json::from_slice(&buf)?;

        Ok(content)
    }

    /// Requests freechains server to post a message.
    ///
    /// Returns message hash.
    pub fn post(
        &mut self,
        signature: Option<&str>,
        encrypt: bool,
        payload: &[u8],
    ) -> Result<String, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        let signature = signature.unwrap_or("anon");
        writeln!(
            stream,
            "{} post {} {} {}",
            self.preamble(),
            signature,
            encrypt,
            payload.len()
        )?;

        stream.write_all(payload)?;

        ChainClient::read_message(&stream)
    }

    /// Requests freechains server to get chain heads.
    pub fn heads(&mut self, blocked: bool) -> Result<Vec<String>, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        let mut msg = String::from("heads");
        if blocked {
            msg = format!("{} blocked", msg);
        }
        writeln!(stream, "{} {}", self.preamble(), &msg)?;

        let response = ChainClient::read_message(&stream)?;
        let hashes = response.split(' ').map(String::from).collect();

        Ok(hashes)
    }

    /// Requests freechains server to traverse all messages hashes starting with required messages
    /// hashes.
    pub fn traverse(&mut self, up_blocks: &[&str]) -> Result<Vec<String>, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(
            stream,
            "{} traverse {}",
            self.preamble(),
            up_blocks.join(" ")
        )?;

        let response = ChainClient::read_message(&stream)?;
        let hashes = response.split(' ').map(String::from).collect();

        Ok(hashes)
    }

    /// Requests freechains server for content reputation.
    pub fn reputation(&mut self, hash: &str) -> Result<usize, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(stream, "{} reps {}", self.preamble(), hash)?;

        let response = ChainClient::read_message(&stream)?;
        let reputation = response.parse()?;

        Ok(reputation)
    }

    /// Requests freechains server to give content a like.
    pub fn like(&mut self, hash: &str, pvtkey: &str, reason: &[u8]) -> Result<String, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(
            stream,
            "{} like 1 {} {} {}",
            self.preamble(),
            hash,
            pvtkey,
            reason.len()
        )?;
        stream.write_all(reason)?;

        let hash = ChainClient::read_message(&stream)?;

        Ok(hash)
    }

    /// Requests freechains server to give content a dislike.
    pub fn dislike(
        &mut self,
        hash: &str,
        pvtkey: &str,
        reason: &[u8],
    ) -> Result<String, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(
            stream,
            "{} like -1 {} {} {}",
            self.preamble(),
            hash,
            pvtkey,
            reason.len()
        )?;
        stream.write_all(reason)?;

        let hash = ChainClient::read_message(&stream)?;

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
/// let mut client = Client::new("host1:8330")?;
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

    fn preamble(&self) -> String {
        format!(
            "{} peer {}:{}",
            self.client.preamble(),
            self.peer.ip(),
            self.peer.port()
        )
    }

    /// Requests freechains server to send chain to other freechains peer.
    pub fn send_chain(&mut self, id: &ChainId) -> Result<(), ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(stream, "{} send {}", self.preamble(), id)?;

        Client::read_message(&stream)?;

        Ok(())
    }

    /// Requests freechains server to receive chain from other freechains peer.
    pub fn receive_chain(&mut self, id: &ChainId) -> Result<(), ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(stream, "{} recv {}", self.preamble(), id)?;

        Client::read_message(&stream)?;

        Ok(())
    }

    /// Requests freechains server to ping other freechains peer.
    pub fn ping(&mut self) -> Result<(), ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(stream, "{} ping", self.preamble())?;
        Client::read_message(&stream)?;
        Ok(())
    }

    /// Requests freechains server to request other freechains peer for their chains.
    pub fn chains(&mut self) -> Result<ChainsIds, ClientError> {
        let mut stream = TcpStream::connect(self.client.addr)?;

        writeln!(stream, "{} chains", self.preamble())?;

        let response = Client::read_message(&stream)?;
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
