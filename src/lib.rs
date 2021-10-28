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
//! let client = Client::new("0.0.0.0:8300");
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
//! let client = Client::new("0.0.0.0:8300");
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
//! let chain_client = client.chain(&chain_id);
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
    pub fn crypto_shared(&self, pwd: &str) -> Result<String, ClientError> {
        let mut stream = self.connector.connect()?;

        writeln!(stream, "{} crypto shared", self.preamble())?;
        writeln!(stream, "{}", pwd)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        parse_server_message(&line)
    }

    /// Requests freechains server to generate public and private key with password `pwd`.
    pub fn crypto_pubpvt(&self, pwd: &str) -> Result<(String, String), ClientError> {
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
    pub fn chains(&self) -> Result<ChainsIds, ClientError> {
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
    pub fn join_chain(&self, chain: &ChainId, keys: &[&str]) -> Result<String, ClientError> {
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
    pub fn chain(&self, chain: &ChainId) -> ChainClient<T> {
        ChainClient::new(self, &chain.to_string())
    }

    /// Gets freechains peer client.
    pub fn peer(&self, peer: impl ToSocketAddrs) -> io::Result<PeerClient<T>> {
        PeerClient::new(self, peer)
    }

    /// Gets freechains host client.
    pub fn host(&self) -> HostClient<T> {
        HostClient::new(self)
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
/// let client = Client::new("0.0.0.0:8300");
/// let chain_id = ChainId::new("$chat")?;
///
/// let client = client.chain(&chain_id);
/// let genesis_hash = client.genesis();
///
/// # Ok(())
/// # }
/// ```
pub struct ChainClient<'a, T> {
    client: &'a Client<T>,
    name: String,
}

impl<'a, T> ChainClient<'a, T>
where
    T: Connect,
{
    fn new(client: &'a Client<T>, name: &str) -> ChainClient<'a, T> {
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
    pub fn genesis(&self) -> Result<String, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} genesis", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        parse_server_message(&line)
    }

    /// Requests freechains server for a payload for the specified post. Post must be identified by
    /// its hash.
    pub fn payload(&self, hash: &str, pvtkey: Option<&str>) -> Result<Vec<u8>, ClientError> {
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
    pub fn content(&self, hash: &str, pvtkey: Option<&str>) -> Result<ContentBlock, ClientError> {
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
        &self,
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
    pub fn heads(&self, blocked: bool) -> Result<Vec<String>, ClientError> {
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
    pub fn traverse(&self, up_blocks: &[&str]) -> Result<Vec<String>, ClientError> {
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
    pub fn reputation(&self, hash: &str) -> Result<usize, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} reps {}", self.preamble(), hash)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let reputation = response.parse()?;

        Ok(reputation)
    }

    /// Requests freechains server to give content a like.
    pub fn like(&self, hash: &str, pvtkey: &str, reason: &[u8]) -> Result<String, ClientError> {
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
    pub fn dislike(&self, hash: &str, pvtkey: &str, reason: &[u8]) -> Result<String, ClientError> {
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
/// let client = Client::new("host1:8330");
/// let client = client.peer("host2:8330")?;
/// let chains = client.chains()?;
///
/// # Ok(())
/// # }
/// ```
pub struct PeerClient<'a, T> {
    client: &'a Client<T>,
    peer: SocketAddr,
}

impl<'a, T> PeerClient<'a, T>
where
    T: Connect,
{
    fn new(client: &'a Client<T>, peer: impl ToSocketAddrs) -> io::Result<PeerClient<'a, T>> {
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
    pub fn send_chain(&self, id: &ChainId) -> Result<(usize, usize), ClientError> {
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
    pub fn receive_chain(&self, id: &ChainId) -> Result<(usize, usize), ClientError> {
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
    pub fn ping(&self) -> Result<usize, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} ping", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let ping = response.parse()?;

        Ok(ping)
    }

    /// Requests freechains server to request other freechains peer for their chains.
    pub fn chains(&self) -> Result<ChainsIds, ClientError> {
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

/// Freechains host client actions. Must be created from [Client].
///
/// # Examples
///
/// Opens host client from server `host:8330` and gets server time in milliseconds from Epoch.
///
/// ```no_run
/// use freechains::{Client, ClientError};
///
/// # fn main() -> Result<(), ClientError> {
/// let client = Client::new("host:8330");
/// let client = client.host();
/// let time = client.time()?;
///
/// # Ok(())
/// # }
/// ```
pub struct HostClient<'a, T> {
    client: &'a Client<T>,
}

impl<'a, T> HostClient<'a, T>
where
    T: Connect,
{
    fn new(client: &'a Client<T>) -> HostClient<'a, T> {
        HostClient { client }
    }

    fn preamble(&self) -> String {
        format!("{} host", self.client.preamble())
    }

    /// Requests freechains server its internal timer.
    ///
    /// Returns milliseconds from Epoch time.
    pub fn time(&self) -> Result<usize, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} now", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let time = response.parse()?;

        Ok(time)
    }

    /// Requests freechains server to change its internal timer.
    ///
    /// `milli` is the time to be set on the server, as milliseconds from Epoch time.
    ///
    /// # Examples
    ///
    /// Set server time to 1970-01-01T00:00.0Z.
    ///
    /// ```no_run
    /// use freechains::{Client, ClientError};
    ///
    /// # fn main() -> Result<(), ClientError> {
    /// let client = Client::new("host:8330");
    /// let client = client.host();
    /// let time = client.set_time(0)?;
    ///
    /// # Ok(())
    /// # }
    ///
    /// ```
    pub fn set_time(&self, milli: usize) -> Result<usize, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} now {}", self.preamble(), milli)?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let response = parse_server_message(&line)?;
        let time = response.parse()?;

        Ok(time)
    }

    /// Requests freechains server path.
    pub fn path(&self) -> Result<String, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} path", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let path = parse_server_message(&line)?;

        Ok(path)
    }

    /// Requests freechains server to stop itself.
    pub fn stop(self) -> Result<bool, ClientError> {
        let mut stream = self.client.connector.connect()?;

        writeln!(stream, "{} stop", self.preamble())?;

        let r = BufReader::new(stream);
        let line = read_utf8_line(r)?;
        let stopped = parse_server_message(&line)?;
        let stopped = stopped == "true";

        Ok(stopped)
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

#[cfg(test)]
mod test {
    use std::cell::RefCell;
    use std::rc::Rc;

    use super::*;

    #[derive(Debug)]
    struct ConnectorMock(ConnectionMock);

    impl ConnectorMock {
        fn new() -> ConnectorMock {
            ConnectorMock(ConnectionMock::new())
        }

        fn read_stream(&self) -> Rc<RefCell<Vec<u8>>> {
            self.0.read_stream()
        }
    }

    impl Connect for ConnectorMock {
        fn connect(&self) -> io::Result<Box<dyn ReadWrite>> {
            Ok(Box::new(self.0.clone()))
        }
    }

    #[derive(Debug)]
    struct ConnectionMock {
        read_stream: Rc<RefCell<Vec<u8>>>,
        write_stream: Rc<RefCell<Vec<u8>>>,
    }

    impl ConnectionMock {
        fn new() -> ConnectionMock {
            let read_stream = Rc::new(RefCell::new(Vec::new()));
            let write_stream = Rc::new(RefCell::new(Vec::new()));

            ConnectionMock {
                read_stream,
                write_stream,
            }
        }

        fn read_stream(&self) -> Rc<RefCell<Vec<u8>>> {
            Rc::clone(&self.read_stream)
        }
    }

    impl ReadWrite for ConnectionMock {}

    impl Read for ConnectionMock {
        fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
            let mut read_stream = self.read_stream.borrow_mut();
            let mut a: &[u8] = read_stream.as_ref();

            let size = a.read(b)?;
            read_stream.drain(..size);
            Ok(size)
        }
    }

    impl Write for ConnectionMock {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            let mut a = self.write_stream.borrow_mut();
            a.write(b)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Clone for ConnectionMock {
        fn clone(&self) -> Self {
            let read_stream = Rc::clone(&self.read_stream);
            let write_stream = Rc::clone(&self.write_stream);

            ConnectionMock {
                read_stream,
                write_stream,
            }
        }
    }

    #[test]
    fn crypto_shared() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let response = b"707E8334560C3FB2852CCCE11F9221FA3594B7DE3919A8BAA5B6DB90FE432E53\n";
        w.replace(response.to_vec());
        let hash = client.crypto_shared("pwd")?;

        assert_eq!(hash.as_bytes(), &response[..response.len() - 1]);

        Ok(())
    }

    #[test]
    fn crypto_pubpvt() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let response = b"646AABC0D78E87574FFCD2E98FF14B08C76D424C7A0ED783CB7B840117A403E3 \
                       707E8334560C3FB2852CCCE11F9221FA3594B7DE3919A8BAA5B6DB90FE432E53646AABC0D78E87574FFCD2E98FF14B08C76D424C7A0ED783CB7B840117A403E3\n";
        w.replace(response.to_vec());
        let (pubkey, pvtkey) = client.crypto_pubpvt("pwd")?;

        let exp_pubkey = "646AABC0D78E87574FFCD2E98FF14B08C76D424C7A0ED783CB7B840117A403E3";
        assert_eq!(pubkey, exp_pubkey);

        let exp_pvtkey = "707E8334560C3FB2852CCCE11F9221FA3594B7DE3919A8BAA5B6DB90FE432E53646AABC0D78E87574FFCD2E98FF14B08C76D424C7A0ED783CB7B840117A403E3";
        assert_eq!(pvtkey, exp_pvtkey);

        Ok(())
    }

    #[test]
    fn chains_join() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat")?;
        let pwd_hash = "707E8334560C3FB2852CCCE11F9221FA3594B7DE3919A8BAA5B6DB90FE432E53";

        let response = b"3E56AE4D17484398F7694C75EA6D3F9FD31C756574B4346D0BA40FB36DAB4501\n";
        w.replace(response.to_vec());
        let hash = client.join_chain(&chain_id, &[pwd_hash])?;

        let exp_hash = &response[..response.len() - 1];
        assert_eq!(hash.as_bytes(), exp_hash);

        Ok(())
    }

    #[test]
    fn chains_list() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let response = b"$chain1 $chain2 #chain3 @chain4\n";
        w.replace(response.to_vec());
        let chains = client.chains()?;

        let exp_chains: Result<Vec<_>, _> = std::str::from_utf8(&response[..response.len() - 1])
            .unwrap()
            .split(' ')
            .map(ChainId::new)
            .collect();
        let exp_chains = exp_chains?;
        assert_eq!(chains, exp_chains);

        Ok(())
    }

    #[test]
    fn chain_leave() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"true\n";
        w.replace(response.to_vec());
        let left = client.chain(&chain_id).leave()?;

        assert_eq!(left, true);

        Ok(())
    }

    #[test]
    fn chain_leave_failed() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"false\n";
        w.replace(response.to_vec());
        let left = client.chain(&chain_id).leave()?;

        assert_eq!(left, false);

        Ok(())
    }

    #[test]
    fn chain_genesis() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"0_3E56AE4D17484398F7694C75EA6D3F9FD31C756574B4346D0BA40FB36DAB4501\n";
        w.replace(response.to_vec());
        let genesis = client.chain(&chain_id).genesis()?;

        let exp_genesis = &response[..response.len() - 1];
        assert_eq!(genesis.as_bytes(), exp_genesis);

        Ok(())
    }

    #[test]
    fn chain_heads() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"1_B8AAB63B4CC2129443F0BEA3F1A7FB16C193FE92C3DB2245EB9062EB07A47159 \
                       2_30F9ABD1FDB2DF44CAF47743AE01FD768B1C2B1952B74A761F32E13D5483BE0E\n";
        w.replace(response.to_vec());
        let heads = client.chain(&chain_id).heads(false)?;

        let exp_heads: Vec<_> = std::str::from_utf8(&response[..response.len() - 1])
            .unwrap()
            .split(' ')
            .map(String::from)
            .collect();
        assert_eq!(heads, exp_heads);

        Ok(())
    }

    #[test]
    fn chain_payload() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"17\nhello,\nok message";
        w.replace(response.to_vec());
        let payload = client.chain(&chain_id).payload("some_hash", None)?;
        let payload = std::str::from_utf8(&payload)?;

        let exp_payload = std::str::from_utf8(response)
            .unwrap()
            .split_once('\n')
            .unwrap()
            .1;
        assert_eq!(payload, exp_payload);

        Ok(())
    }

    #[test]
    fn chain_content_block() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();
        let response = br#"710
{
    "hash": "2_3D9997F5D8A57B26B7DEC3BCDFD3A12EAE48C585DFC287FE9DE522E44A96DB46",
    "time": 1635174995341,
    "pay": {
        "crypt": false,
        "hash": "FD7B3E075AB7E245506323F1D1B55330CCD606FB3301F4CABA25022A1DE50B47"
    },
    "like": {
        "n": 1,
        "hash": "1_59C6AA0E3B3650D44D27EB8EF3645ECFC69A1B78F0DAA74A2B89167538749103"
    },
    "sign": {
        "hash": "9EB2D4CB0AC67B35B78B545E4AB3410DC82E6D0778DECFC80C83A13BEAD05F7B83D5B8B6CE67AB7EF9E0CA09FA489AE88FB0D126C522A0ED4E2C5BF939901205",
        "pub": "197154707DAF7953BE0EBB7BBE29FA1AECA402505E9ED00BCAF189EB6A32FCE8"
    },
    "backs": [
        "1_59C6AA0E3B3650D44D27EB8EF3645ECFC69A1B78F0DAA74A2B89167538749103"
    ]
}"#;

        w.replace(response.to_vec());
        let content = client.chain(&chain_id).content("some_hash", None)?;

        let exp_content = ContentBlock {
            hash: "2_3D9997F5D8A57B26B7DEC3BCDFD3A12EAE48C585DFC287FE9DE522E44A96DB46".to_string(),
            time: 1635174995341,
            payload: Some(PayloadBlock {
                crypt: false,
                hash: "FD7B3E075AB7E245506323F1D1B55330CCD606FB3301F4CABA25022A1DE50B47"
                    .to_string(),
            }),
            like: Some(LikeBlock {
                n: 1,
                hash: "1_59C6AA0E3B3650D44D27EB8EF3645ECFC69A1B78F0DAA74A2B89167538749103"
                    .to_string(),
            }),
            signature: Some(SignatureBlock {
                hash:"9EB2D4CB0AC67B35B78B545E4AB3410DC82E6D0778DECFC80C83A13BEAD05F7B83D5B8B6CE67AB7EF9E0CA09FA489AE88FB0D126C522A0ED4E2C5BF939901205".to_string(),
        pubkey: "197154707DAF7953BE0EBB7BBE29FA1AECA402505E9ED00BCAF189EB6A32FCE8".to_string(),
            }),
            backs: vec![
        "1_59C6AA0E3B3650D44D27EB8EF3645ECFC69A1B78F0DAA74A2B89167538749103".to_string()],
        };
        assert_eq!(content, exp_content);

        Ok(())
    }

    #[test]
    fn chain_post() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"3_9B144EE0518E5DE01D4C1AABD469D85315715CB15F77AB4B3D87D7802EE970E6\n";
        w.replace(response.to_vec());
        let hash = client.chain(&chain_id).post(None, false, b"payload")?;

        let exp_hash = std::str::from_utf8(&response[..response.len() - 1]).unwrap();
        assert_eq!(hash, exp_hash);

        Ok(())
    }

    #[test]
    fn chain_like() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"2_3D9997F5D8A57B26B7DEC3BCDFD3A12EAE48C585DFC287FE9DE522E44A96DB46\n";
        w.replace(response.to_vec());

        let fake_hash = "1_9B144EE0518E5DE01D4C1AABD469D85315715CB15F77AB4B3D87D7802EE970E6";
        let hash = client
            .chain(&chain_id)
            .like(&fake_hash, "pvt_key", b"i liked it")?;

        let exp_hash = std::str::from_utf8(&response[..response.len() - 1]).unwrap();
        assert_eq!(hash, exp_hash);

        Ok(())
    }

    #[test]
    fn chain_dislike() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"2_3D9997F5D8A57B26B7DEC3BCDFD3A12EAE48C585DFC287FE9DE522E44A96DB46\n";
        w.replace(response.to_vec());

        let fake_hash = "1_9B144EE0518E5DE01D4C1AABD469D85315715CB15F77AB4B3D87D7802EE970E6";
        let hash = client
            .chain(&chain_id)
            .dislike(&fake_hash, "pvt_key", b"i liked it")?;

        let exp_hash = std::str::from_utf8(&response[..response.len() - 1]).unwrap();
        assert_eq!(hash, exp_hash);

        Ok(())
    }

    #[test]
    fn chain_reputation() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"18\n";
        w.replace(response.to_vec());

        let fake_hash = "1_9B144EE0518E5DE01D4C1AABD469D85315715CB15F77AB4B3D87D7802EE970E6";
        let reps = client.chain(&chain_id).reputation(&fake_hash)?;

        let exp_reps = 18;
        assert_eq!(reps, exp_reps);

        Ok(())
    }

    #[test]
    fn chain_traverse() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let chain_id = ChainId::new("$chat").unwrap();

        let response = b"1_B8AAB63B4CC2129443F0BEA3F1A7FB16C193FE92C3DB2245EB9062EB07A47159 \
                       2_30F9ABD1FDB2DF44CAF47743AE01FD768B1C2B1952B74A761F32E13D5483BE0E \
                       3_3D9997F5D8A57B26B7DEC3BCDFD3A12EAE48C585DFC287FE9DE522E44A96DB46\n";
        w.replace(response.to_vec());

        let fake_hash = "0_9B144EE0518E5DE01D4C1AABD469D85315715CB15F77AB4B3D87D7802EE970E6";
        let hashes = client.chain(&chain_id).traverse(&[fake_hash])?;

        let exp_hahses: Vec<_> = std::str::from_utf8(&response[..response.len() - 1])
            .unwrap()
            .split(' ')
            .map(String::from)
            .collect();
        assert_eq!(hashes, exp_hahses);

        Ok(())
    }

    #[test]
    fn peer_ping() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let fake_peer = "1.2.3.4:8330";

        let response = b"10\n";
        w.replace(response.to_vec());

        let ping = client.peer(&fake_peer)?.ping()?;

        let exp_ping = 10;
        assert_eq!(ping, exp_ping);

        Ok(())
    }

    #[test]
    fn peer_chains_list() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let fake_peer = "1.2.3.4:8330";

        let response = b"$chain1 $chain2 #chain3 @chain4\n";
        w.replace(response.to_vec());
        let chains = client.peer(&fake_peer)?.chains()?;

        let exp_chains: Result<Vec<_>, _> = std::str::from_utf8(&response[..response.len() - 1])
            .unwrap()
            .split(' ')
            .map(ChainId::new)
            .collect();
        let exp_chains = exp_chains?;
        assert_eq!(chains, exp_chains);

        Ok(())
    }

    #[test]
    fn peer_send() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let fake_peer = "1.2.3.4:8330";
        let chain_id = ChainId::new("#forum").unwrap();

        let response = b"5 / 8\n";
        w.replace(response.to_vec());

        let sent = client.peer(&fake_peer)?.send_chain(&chain_id)?;

        let exp_sent = (5, 8);
        assert_eq!(sent, exp_sent);

        Ok(())
    }

    #[test]
    fn peer_receive() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let fake_peer = "1.2.3.4:8330";
        let chain_id = ChainId::new("#forum").unwrap();

        let response = b"5 / 8\n";
        w.replace(response.to_vec());

        let received = client.peer(&fake_peer)?.receive_chain(&chain_id)?;

        let exp_received = (5, 8);
        assert_eq!(received, exp_received);

        Ok(())
    }

    #[test]
    fn host_get_time() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let response = b"1635310954\n";
        w.replace(response.to_vec());

        let time = client.host().time()?;

        let exp_time = 1635310954;
        assert_eq!(time, exp_time);

        Ok(())
    }

    #[test]
    fn host_set_time() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let response = b"1635310954\n";
        w.replace(response.to_vec());

        let time = client.host().set_time(1635310954)?;

        let exp_time = 1635310954;
        assert_eq!(time, exp_time);

        Ok(())
    }

    #[test]
    fn host_path() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let response = b"/tmp/freechains\n";
        w.replace(response.to_vec());

        let path = client.host().path()?;

        let exp_path = std::str::from_utf8(&response[..response.len() - 1]).unwrap();
        assert_eq!(path, exp_path);

        Ok(())
    }

    #[test]
    fn host_stop() -> Result<(), Box<dyn Error>> {
        let mock = ConnectorMock::new();
        let w = mock.read_stream();
        let client = Client::new(mock);

        let response = b"true\n";
        w.replace(response.to_vec());

        let stopped = client.host().stop()?;

        let exp_stopped = true;
        assert_eq!(stopped, exp_stopped);

        Ok(())
    }
}
