//! Top level libraries for remote ping

#![warn(
    missing_debug_implementations,
    rust_2018_idioms,
    missing_docs,
    rustdoc::missing_doc_code_examples
)]

use std::{error::Error, path::Path};
use std::io::prelude::*;
use std::net::TcpStream;

/// Container for data used to create SSH connection
#[derive(Debug)]
pub struct Host<'host> {
    /// Hostname / IP Address and Port in the format of host:port
    pub connection_string: &'host str,
    /// Authenication information for SSH connection
    pub auth_method: AuthMethod<'host>,
}

/// TypeState used to represent an initialized SSH connection
/// This TypeState is returned after successfully negotiating a TCP
/// connection and starting the SSH Session
/// You can inspect this type, but you cannot initialize it directly
#[derive(Debug)]
pub struct Connection<'host> {
    /// Host at remote end of Connection
    pub host: Host<'host>,
    /// Transport wrapper holding the active SSH Session
    transport: Transport,
}

/// TypeState used to represent an authenticated ssh `Connection`
/// An AuthenticatedConnection is returned after the remote device successfully
/// authenticates the user using the `AuthMethod` provided when initializing a `Host`.
/// You can inspect this type, but you cannot initialize it directly
#[derive(Debug)]
pub struct AuthenticatedConnection<'host> {
    /// Host at remote end of AuthenticatedConnection
    pub host: Host<'host>,
    /// Transport wrapper holding the active SSH Session
    transport: Transport,
}

/// AuthMethods are used to specify the strategy to be used for authenticating
/// an ssh `Connection`.
#[derive(Debug)]
pub enum AuthMethod<'auth> {
    /// Basic Password Authentication
    /// NOTE: This is not the same as KeyboardInteractive
    BasicAuth {
        /// Username of ssh user
        username: &'auth str,
        /// Password of ssh user
        password: &'auth str,
    },
    /// PublicKey Authentication
    PublicKey {
        /// Username of ssh user
        username: &'auth str,
        /// Path to public ssh key (optional)
        public_key: Option<&'auth Path>,
        /// Path to private ssh key
        private_key: &'auth Path,
        /// Password for private key (optional)
        password: Option<&'auth str>,
    },
}

// Debug is not implemented for ssh2::Session, preventing us from using derive.
// We use a wrapper struct here to allow us to create a simple representation.
struct Transport {
    session: ssh2::Session,
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Transport")
            .field("session", &"ssh2::Session")
            .finish()
    }
}

// TODO This leads to opaque errors, may want to
// consider creating a proper error type
type ConnResult<T> = Result<T, Box<dyn Error>>;

/// Create a `Connection` to a `Host`
///
/// ```
/// use rping::*;
/// let connection_string = "0.0.0.0:2222";
/// let auth_method = AuthMethod::BasicAuth { username: "admin", password: "t0p-Secret" };
/// let host = Host {
///     connection_string,
///     auth_method,
/// };
/// let connection = connect(host);
/// assert!(connection.is_ok());
///
pub fn connect(host: Host<'_>) -> ConnResult<Connection<'_>> {
    let tcp = TcpStream::connect(host.connection_string)?;
    let mut session = ssh2::Session::new()?;
    session.set_tcp_stream(tcp);
    session.handshake()?;
    let transport = Transport { session };
    Ok(Connection { host, transport })
}

/// Authenticate a ssh `Connection`
///
/// ```
/// use rping::*;
/// let connection_string = "0.0.0.0:2222";
/// let auth_method = AuthMethod::BasicAuth { username: "admin", password: "t0p-Secret" };
/// let host = Host {
///     connection_string,
///     auth_method,
/// };
/// let authentication = connect(host).and_then(authenticate);
/// assert!(authentication.is_ok());
///
pub fn authenticate(conn: Connection<'_>) -> ConnResult<AuthenticatedConnection<'_>> {
    match &conn.host.auth_method {
        AuthMethod::BasicAuth { username, password } => {
            conn.transport.session.userauth_password(username, password)?;
        },
        AuthMethod::PublicKey {username, public_key, private_key, password} => {
            conn.transport.session
                .userauth_pubkey_file(username, *public_key, private_key, *password)?;
        }
    }
    Ok(AuthenticatedConnection {
        host: conn.host,
        transport: conn.transport,
    })
}

/// Sends a command to a remote device via SSH
///
/// ```
/// use rping::*;
/// let connection_string = "0.0.0.0:2222";
/// let auth_method = AuthMethod::BasicAuth { username: "admin", password: "t0p-Secret" };
/// let host = Host {
///     connection_string,
///     auth_method,
/// };
/// let connection = connect(host).and_then(authenticate).unwrap();
/// let result = send_command(&connection, "ping 8.8.8.8 -c 1");
/// assert!(result.is_ok());
///
pub fn send_command<'h>(conn: &AuthenticatedConnection<'h>, command: &str) -> ConnResult<String> {
    let mut output = String::new();
    let mut channel = conn.transport.session.channel_session()?;
    channel.exec(command)?;
    channel.read_to_string(&mut output)?;
    channel.wait_close()?;
    channel.exit_status()?;
    Ok(output)
}

/// Example function showing how the methods can be composed to ping via remote hosts
/// Sends three pings from the `Host` to the destination ip address / hostname
///
/// ```
/// use rping::*;
/// let connection_string = "0.0.0.0:2222";
/// let auth_method = AuthMethod::BasicAuth { username: "admin", password: "t0p-Secret" };
/// let host = Host {
///     connection_string,
///     auth_method,
/// };
/// let result = remote_ping(host, "8.8.8.8");
/// assert!(result.is_ok());
///
pub fn remote_ping(source: Host<'_>, destination: &str) -> ConnResult<String> {
    let connection = connect(source).and_then(authenticate).unwrap();
    let command = format!("ping {} -c 3", destination);
    let result = send_command(&connection, &command)?;
    Ok(result)
}
