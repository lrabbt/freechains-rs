//! The `freechains` module implements freechains client utilities.
//!
//! Main use comes from [Client] struct.
//!
//! # Examples
//!
//! List all server chains.
//!
//! ```no_run
//! use freechains::{Client, ClientError};
//!
//! # fn main() -> Result<(), ClientError> {
//! let mut client = Client::new("0.0.0.0:8300");
//! let chain_ids = client.chains()?;
//! # Ok(())
//! # }
//! ```
//!
//! Join and post on a public chain.
//!
//! ```no_run
//! use freechains::{Client, ChainId, ClientError};
//!
//! # fn main() -> Result<(), ClientError> {
//! let mut client = Client::new("0.0.0.0:8300");
//!
//! // Join public chain
//! let chain_id = ChainId::new("#forum")?;
//! # let chain_pubkey1 = "";
//! # let chain_pubkey2 = "";
//! client.join_chain(&chain_id, &[chain_pubkey1, chain_pubkey2])?;
//!
//! // Generate public and private keys
//! let (pubkey, pvtkey) = client.crypto_pubpvt("strong_password")?;
//!
//! let mut chain_client = client.chain(&chain_id);
//!
//! // Post on public chain
//! chain_client.post(Some(&pvtkey), false, b"Hello, forum!")?;
//! # Ok(())
//! # }
//! ```
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

use serde::{Deserialize, Serialize};

use std::convert::TryFrom;
use std::error::Error;
use std::fmt;
use std::io::prelude::*;
use std::io::{self, BufReader};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::num;

/// A trait for objects that implements [Read] and [Write].
pub trait ReadWrite: Read + Write {}

impl ReadWrite for TcpStream {}

/// A trait for objects that can connect to a [ReadWrite] stream.
pub trait Connect: fmt::Debug {
    /// Connects to [ReadWrite] stream.
    fn connect(&self) -> io::Result<Box<dyn ReadWrite>>;
}

impl Connect for str {
    fn connect(&self) -> io::Result<Box<dyn ReadWrite>> {
        Ok(Box::new(TcpStream::connect(self)?))
    }
}
impl Connect for &str {
    fn connect(&self) -> io::Result<Box<dyn ReadWrite>> {
        Ok(Box::new(TcpStream::connect(self)?))
    }
}

/// Connector which uses [TcpStream] as underlying stream.
#[derive(Debug)]
pub struct TcpStreamConnector<T>
where
    T: fmt::Debug,
{
    addrs: T,
}

impl<T> TcpStreamConnector<T>
where
    T: ToSocketAddrs + fmt::Debug,
{
    /// Creates new [TcpStreamConnector].
    pub fn new(addrs: T) -> TcpStreamConnector<T> {
        TcpStreamConnector { addrs }
    }
}

impl<T> Connect for TcpStreamConnector<T>
where
    T: ToSocketAddrs + fmt::Debug,
{
    fn connect(&self) -> io::Result<Box<dyn ReadWrite>> {
        let stream = TcpStream::connect(&self.addrs)?;
        Ok(Box::new(stream))
    }
}

/// Freechains host version supported.
pub const HOST_VERSION: (u8, u8, u8) = (0, 8, 6);

/// Freechains client. For more usage examples, check [module documentation](self),
///
/// Due to freechains server limitations, a new TCP connection is opened for each client request.
///
/// # Examples
///
/// Create client from [str].
///
/// ```
/// use freechains::Client;
///
/// let client = Client::new("0.0.0.0:8330");
/// ```
#[derive(Debug)]
pub struct Client<T> {
    connector: T,
}

impl<T> Client<T>
where
    T: Connect,
{
    /// Creates a freechains client.
    pub fn new(connector: T) -> Client<T> {
        Client { connector }
    }

    fn preamble(&self) -> String {
        format!(
            "FC v{}.{}.{}",
            HOST_VERSION.0, HOST_VERSION.1, HOST_VERSION.2
        )
    }

    /// Requests freechains server for a symmetric encryption for password `pwd`.
    pub fn crypto_shared(&mut self, pwd: &str) -> Result<String, ClientError> {
        let mut stream = self.connector.connect()?;

        writeln!(stream, "{} crypto shared", self.preamble())?;
        writeln!(stream, "{}", pwd)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        parse_server_message(&line)
    }

    /// Requests freechains server to generate public and private key with password `pwd`.
    pub fn crypto_pubpvt(&mut self, pwd: &str) -> Result<(String, String), ClientError> {
        let mut stream = self.connector.connect()?;

        writeln!(stream, "{} crypto pubpvt", self.preamble())?;
        writeln!(stream, "{}", pwd)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let line = parse_server_message(&line)?;

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
        let mut stream = self.connector.connect()?;

        writeln!(stream, "{} chains list", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let line = parse_server_message(&line)?;

        let chains: Result<Vec<_>, _> = line.split(' ').map(ChainId::new).collect();
        let chains = chains?;

        Ok(chains)
    }

    /// Requests freechains server to join private chain with creators defined by keys.
    ///
    /// Returns created chain hash.
    pub fn join_chain(&mut self, chain: &ChainId, keys: &[&str]) -> Result<String, ClientError> {
        let mut stream = self.connector.connect()?;

        writeln!(
            stream,
            "{} chains join {} {}",
            self.preamble(),
            chain,
            keys.join(" ")
        )?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let hash = parse_server_message(&line)?;

        Ok(hash)
    }

    /// Gets freechains chain client.
    pub fn chain(&mut self, chain: &ChainId) -> ChainClient<T> {
        ChainClient::new(self, &chain.to_string())
    }

    /// Gets freechains peer client.
    pub fn peer(&mut self, peer: impl ToSocketAddrs) -> io::Result<PeerClient<T>> {
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
/// let mut client = Client::new("0.0.0.0:8300");
/// let chain_id = ChainId::new("$chat")?;
///
/// let mut client = client.chain(&chain_id);
/// let genesis_hash = client.genesis();
///
/// # Ok(())
/// # }
/// ```
pub struct ChainClient<'a, T> {
    client: &'a mut Client<T>,
    name: String,
}

impl<'a, T> ChainClient<'a, T>
where
    T: Connect,
{
    fn new(client: &'a mut Client<T>, name: &str) -> ChainClient<'a, T> {
        let name = String::from(name);
        ChainClient { client, name }
    }

    fn preamble(&self) -> String {
        format!("{} chain {}", self.client.preamble(), self.name)
    }

    /// Returns chain name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Requests freechains server to leave chain.
    pub fn leave(self) -> Result<bool, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(
            stream,
            "{} chains leave {}",
            self.client.preamble(),
            self.name
        )?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let line = parse_server_message(&line)?;
        let left = line == "true";

        Ok(left)
    }

    /// Requests freechains for the hash of genesis.
    pub fn genesis(&mut self) -> Result<String, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} genesis", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        parse_server_message(&line)
    }

    /// Requests freechains server for a payload for the specified post. Post must be identified by
    /// its hash.
    pub fn payload(&mut self, hash: &str, pvtkey: Option<&str>) -> Result<Vec<u8>, ClientError> {
        let mut stream = self.client.connector.connect()?;

        let pvtkey = pvtkey.unwrap_or("null");
        writeln!(
            stream,
            "{} get payload {} {}",
            self.preamble(),
            hash,
            pvtkey
        )?;

        let mut r = BufReader::new(stream);
        let payload_size = read_utf8_line(&mut r)?;
        let payload_size = parse_server_message(&payload_size)?;
        let payload_size = payload_size.parse()?;

        let mut buf = vec![0; payload_size];
        r.read_exact(&mut buf)?;

        Ok(buf.to_vec())
    }

    /// Requests freechains server for a block of content. Content must be identified by its hash.
    pub fn content(
        &mut self,
        hash: &str,
        pvtkey: Option<&str>,
    ) -> Result<ContentBlock, ClientError> {
        let mut stream = self.client.connector.connect()?;

        let pvtkey = pvtkey.unwrap_or("null");
        writeln!(stream, "{} get block {} {}", self.preamble(), hash, pvtkey)?;

        let mut r = BufReader::new(stream);
        let block_size = read_utf8_line(&mut r)?;
        let block_size = parse_server_message(&block_size)?;
        let block_size = block_size.parse()?;

        let mut buf = vec![0; block_size];
        r.read_exact(&mut buf)?;

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
        let mut stream = self.client.connector.connect()?;

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

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        parse_server_message(&line)
    }

    /// Requests freechains server to get chain heads.
    pub fn heads(&mut self, blocked: bool) -> Result<Vec<String>, ClientError> {
        let mut stream = self.client.connector.connect()?;

        let mut msg = String::from("heads");
        if blocked {
            msg = format!("{} blocked", msg);
        }
        writeln!(stream, "{} {}", self.preamble(), &msg)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let hashes = response.split(' ').map(String::from).collect();

        Ok(hashes)
    }

    /// Requests freechains server to traverse all messages hashes starting with required messages
    /// hashes.
    pub fn traverse(&mut self, up_blocks: &[&str]) -> Result<Vec<String>, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(
            stream,
            "{} traverse {}",
            self.preamble(),
            up_blocks.join(" ")
        )?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let hashes = response.split(' ').map(String::from).collect();

        Ok(hashes)
    }

    /// Requests freechains server for content reputation.
    ///
    /// Accepts either a post hash, or an user public key.
    pub fn reputation(&mut self, hash: &str) -> Result<usize, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} reps {}", self.preamble(), hash)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let reputation = response.parse()?;

        Ok(reputation)
    }

    /// Requests freechains server to give content a like.
    pub fn like(&mut self, hash: &str, pvtkey: &str, reason: &[u8]) -> Result<String, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(
            stream,
            "{} like 1 {} {} {}",
            self.preamble(),
            hash,
            pvtkey,
            reason.len()
        )?;
        stream.write_all(reason)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        parse_server_message(&line)
    }

    /// Requests freechains server to give content a dislike.
    pub fn dislike(
        &mut self,
        hash: &str,
        pvtkey: &str,
        reason: &[u8],
    ) -> Result<String, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(
            stream,
            "{} like -1 {} {} {}",
            self.preamble(),
            hash,
            pvtkey,
            reason.len()
        )?;
        stream.write_all(reason)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        parse_server_message(&line)
    }
}

impl<T> fmt::Display for ChainClient<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.name.fmt(f)
    }
}

impl<T> fmt::Debug for ChainClient<'_, T> {
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
/// let mut client = Client::new("host1:8330");
/// let mut client = client.peer("host2:8330")?;
/// let chains = client.chains()?;
///
/// # Ok(())
/// # }
/// ```
pub struct PeerClient<'a, T> {
    client: &'a mut Client<T>,
    peer: SocketAddr,
}

impl<'a, T> PeerClient<'a, T>
where
    T: Connect,
{
    fn new(client: &'a mut Client<T>, peer: impl ToSocketAddrs) -> io::Result<PeerClient<'a, T>> {
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
    pub fn send_chain(&mut self, id: &ChainId) -> Result<(usize, usize), ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} send {}", self.preamble(), id)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;

        let mut response_split = response.split('/');
        let sent = response_split
            .next()
            .ok_or(ClientError::InvalidServerResponseError(response.clone()))?;
        let sent = sent.trim().parse()?;
        let total = response_split
            .next()
            .ok_or(ClientError::InvalidServerResponseError(response.clone()))?;
        let total = total.trim().parse()?;

        Ok((sent, total))
    }

    /// Requests freechains server to receive chain from other freechains peer.
    pub fn receive_chain(&mut self, id: &ChainId) -> Result<(usize, usize), ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} recv {}", self.preamble(), id)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;

        let mut response_split = response.split('/');
        let recv = response_split
            .next()
            .ok_or(ClientError::InvalidServerResponseError(response.clone()))?;
        let recv = recv.trim().parse()?;
        let total = response_split
            .next()
            .ok_or(ClientError::InvalidServerResponseError(response.clone()))?;
        let total = total.trim().parse()?;

        Ok((recv, total))
    }

    /// Requests freechains server to ping other freechains peer.
    ///
    /// Returns ping time in milliseconds.
    pub fn ping(&mut self) -> Result<usize, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} ping", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let ping = response.parse()?;

        Ok(ping)
    }

    /// Requests freechains server to request other freechains peer for their chains.
    pub fn chains(&mut self) -> Result<ChainsIds, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} chains", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let chains: Result<Vec<_>, _> = response.split(' ').map(ChainId::new).collect();
        let chains = chains?;

        Ok(chains)
    }
}

/// Type of freechains chain.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
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

/// Vector of chain ids.
pub type ChainsIds = Vec<ChainId>;

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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ContentBlock {
    /// Content hash.
    pub hash: String,
    /// Content instant of creation. Milliseconds since [std::time::UNIX_EPOCH].
    pub time: usize,
    /// Content payload information.
    #[serde(rename(serialize = "pay", deserialize = "pay"))]
    pub payload: Option<PayloadBlock>,
    /// If content is a like, like information is stored here.
    pub like: Option<LikeBlock>,
    /// Content signature information.
    #[serde(rename(serialize = "sign", deserialize = "sign"))]
    pub signature: Option<SignatureBlock>,
    /// Blocks which points to this content block.
    pub backs: Vec<String>,
}

/// Representation of freechains payload field from content block response [ContentBlock].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PayloadBlock {
    /// Payload hash.
    pub hash: String,
    /// If payload is encrypted.
    pub crypt: bool,
}

/// Representation of freechains like field from content block response [ContentBlock].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LikeBlock {
    /// Like hash.
    pub hash: String,
    /// Defines if is a like or a dislike. `1` is a like, `-1` is a dislike.
    pub n: usize,
}

/// Representation of freechains signature field from content block response [ContentBlock].
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SignatureBlock {
    /// Signature hash.
    pub hash: String,
    /// Signature public key.
    #[serde(rename(serialize = "pub", deserialize = "pub"))]
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
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct InvalidChainNameError;

impl Error for InvalidChainNameError {}

impl fmt::Display for InvalidChainNameError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "chain name must start with '$', '@' or '#'")
    }
}

fn read_utf8_line(mut stream: impl BufRead) -> io::Result<String> {
    let mut line = String::new();
    let size = stream.read_line(&mut line)?;
    if size > 0 && line.chars().last().expect("must have last character") == '\n' {
        line = String::from(&line[..size - 1]);
    }

    Ok(line)
}

fn parse_server_message(msg: &str) -> Result<String, ClientError> {
    if msg.len() < 2 {
        return Err(ClientError::EmptyResponseError);
    }

    let mut chars = msg.chars();

    let first_char = chars.next();
    if let Some(c) = first_char {
        if c == '!' {
            chars.next();
            return Err(ClientError::ExecutionError(chars.collect()));
        }
    }

    Ok(String::from(msg))
}
