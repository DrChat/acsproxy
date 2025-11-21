use std::{net::SocketAddr, path::PathBuf, str::FromStr, sync::Arc};

use anyhow::Context;
use azure_core::auth::TokenCredential;
use base64::{Engine, prelude::BASE64_STANDARD};
use clap::Parser;
use clap_verbosity_flag::{InfoLevel, LevelFilter, Verbosity};
use figment::{Figment, providers::Format};
use mail_parser::{MessageParser, MimeHeaders};
use regex::Regex;
use serde::Deserialize;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
};
use url::Url;

mod acs;

trait StringExt {
    fn split_once_opt(&self, delimiter: &str) -> (&'_ str, Option<&'_ str>);
}

impl StringExt for &str {
    #[inline]
    fn split_once_opt(&self, delimiter: &str) -> (&'_ str, Option<&'_ str>) {
        self.split_once(delimiter)
            .map_or((self, None), |(l, r)| (l, Some(r)))
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct SmtpStatus(u32);

impl SmtpStatus {
    // RFC 5321, section 4.2.2
    // https://www.rfc-editor.org/rfc/rfc5321#section-4.2.2
    const SERVICE_READY: Self = Self(220);
    const BYE: Self = Self(221);
    const OK: Self = Self(250);

    const START_MAIL_INPUT: Self = Self(354);

    const ERROR_PROCESSING: Self = Self(451);
    const ERROR_SYNTAX: Self = Self(500);
    const ERROR_FORMAT: Self = Self(501);
    const ERROR_CMD_NOT_IMPLEMENTED: Self = Self(502);
    const ERROR_BAD_SEQUENCE: Self = Self(503);
    const ERROR_MAILBOX_UNAVAILABLE: Self = Self(550);
}

#[derive(Debug, Clone, PartialEq)]
struct SmtpResult {
    code: SmtpStatus,
    mesg: String,
}

impl std::fmt::Display for SmtpResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.code.0, self.mesg)
    }
}

impl SmtpResult {
    fn new(status: SmtpStatus, msg: impl Into<String>) -> Self {
        Self {
            code: status,
            mesg: msg.into(),
        }
    }

    /// Shorthand to construct a result that represents "250 Ok"
    fn ok() -> Self {
        Self {
            code: SmtpStatus::OK,
            mesg: "Ok".to_string(),
        }
    }

    /// Shorthand for a result that represents "500 syntax error"
    fn err_syntax() -> Self {
        Self {
            code: SmtpStatus::ERROR_SYNTAX,
            mesg: "Syntax error".to_string(),
        }
    }

    /// Shorthand for a result that represents "502 not implemented"
    fn err_not_implemented() -> Self {
        Self {
            code: SmtpStatus::ERROR_CMD_NOT_IMPLEMENTED,
            mesg: "Not implemented".to_string(),
        }
    }

    /// Shorthand for a result that represents "503 bad sequence"
    fn err_bad_sequence() -> Self {
        Self {
            code: SmtpStatus::ERROR_BAD_SEQUENCE,
            mesg: "Bad sequence".to_string(),
        }
    }

    /// Convert the result into a byte vector.
    fn into_bytes(&self) -> Vec<u8> {
        if self.mesg.contains('\n') {
            // Multiline reply.
            let mut lines = self.mesg.split("\n").peekable();
            let mut result = String::new();

            while let Some(line) = lines.next() {
                if lines.peek().is_none() {
                    // Last line; use a space separator.
                    result.push_str(&format!("{} {}\r\n", self.code.0, line));
                } else {
                    // Continuing response.
                    result.push_str(&format!("{}-{}\r\n", self.code.0, line));
                }
            }

            return result.into_bytes();
        }

        format!("{} {}\r\n", self.code.0, self.mesg).into_bytes()
    }
}

impl FromStr for SmtpResult {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let line = s.trim_end_matches("\r\n");

        if let Some((code_str, message)) = line.split_once(' ') {
            if let Ok(code) = code_str.parse::<u32>() {
                return Ok(Self {
                    code: SmtpStatus(code),
                    mesg: message.to_string(),
                });
            }
        }

        // Malformed response - return error
        Err(format!("Invalid SMTP response: {}", line))
    }
}

#[derive(Deserialize, Debug, Clone)]
struct AppConfig {
    /// Address to listen to for incoming requests
    listen_address: Option<SocketAddr>,
    /// The Azure Communication Services endpoint
    endpoint: Url,
}

#[derive(Parser, Debug, Clone)]
struct Args {
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,

    /// Path to the configuration file
    #[arg(short, long, default_value = "default.toml")]
    config: PathBuf,
}

async fn handle_connection(
    stream: TcpStream,
    mut send_mail: impl AsyncFnMut(acs::EmailMessage) -> SmtpResult,
) -> anyhow::Result<()> {
    // Minimum implementation (RFC 5321, section 4.5.1)
    // EHLO
    // HELO
    // MAIL
    // RCPT
    // DATA
    // RSET
    // NOOP
    // QUIT
    // VRFY
    //
    // Additional commands:
    // STARTTLS: https://stackoverflow.com/questions/78329706/upgrading-tcpstream-to-tls-on-mail-server

    // The last received command.
    let mut last_cmd = String::new();

    let (r, mut w) = stream.into_split();

    let mut send = None;
    let mut rcpt = Vec::<String>::new();

    w.write_all(&SmtpResult::new(SmtpStatus::SERVICE_READY, "Service ready").into_bytes())
        .await
        .context("failed to send greeting")?;

    // Max line length: https://www.rfc-editor.org/rfc/rfc5321#section-4.5.3.1.6
    let mut bs = BufReader::new(r);
    loop {
        let mut buf = String::new();

        bs.read_line(&mut buf)
            .await
            .context("failed to read command")?;

        // The SMTP state machine is defined by RFC 5321, section 4.3.1:
        // https://www.rfc-editor.org/rfc/rfc5321#section-4.3.1

        // Strip off the trailing `\r\n`.
        let buf = buf.strip_suffix("\r\n").unwrap_or(&buf);

        // DEBUG: Print the received line.
        tracing::debug!("=> {buf}");

        let resp = {
            // Split the verb from the parameter. If there is no parameter, default to a blank string.
            let (cmd, param) = buf.split_once_opt(" ");
            let param = param.unwrap_or("");

            // RFC 5321, section 3.3: Mail Transactions
            //    There are three steps to SMTP mail transactions. The transaction
            //    starts with a MAIL command that gives the sender identification.
            //    A series of one or more RCPT
            //    commands follows, giving the receiver information.  Then, a DATA
            //    command initiates transfer of the mail data and is terminated by the
            //    "end of mail" data indicator, which also confirms the transaction.

            let f = async {
                match cmd {
                    // RFC 5321, section 4.1.1.1
                    // HELO SP Domain <CRLF>
                    "HELO" => SmtpResult::new(SmtpStatus::OK, format!("Hello {param}")),
                    // RFC 5321, section 4.1.1.1
                    // EHLO SP (Domain / address-literal) <CRLF>
                    // (This command supersedes HELO)
                    "EHLO" => {
                        // Write out server extensions. E.g from ACS:
                        // 250-ic3-transport-smtp-acs-deployment-74764d7bb6-f5xpg Hello [108.238.244.173]
                        // 250-SIZE 31457280
                        // 250-STARTTLS
                        // 250 CHUNKING

                        SmtpResult::new(SmtpStatus::OK, format!("localhost"))
                    }
                    // RFC 5321, section 4.1.1.2
                    // MAIL FROM:<reverse-path> <CRLF>
                    "MAIL" => {
                        let re = Regex::new(r"FROM:<(.*)>").unwrap();
                        let address = if let Some(matches) = re.captures(param) {
                            matches.get(1).unwrap().as_str().to_string()
                        } else {
                            return SmtpResult::err_syntax();
                        };

                        if last_cmd != "HELO" && last_cmd != "EHLO" {
                            return SmtpResult::err_bad_sequence();
                        }

                        // Reset the internal buffers.
                        send = Some(address);
                        rcpt = Vec::new();
                        SmtpResult::ok()
                    }
                    // RFC 5321, section 4.1.1.3
                    // RCPT TO:<forward-path> [ SP <rcpt-parameters> ] <CRLF>
                    "RCPT" => {
                        let re = Regex::new(r"TO:<(.*)>").unwrap();
                        let address = if let Some(matches) = re.captures(param) {
                            matches.get(1).unwrap().as_str().to_string()
                        } else {
                            return SmtpResult::err_syntax();
                        };

                        if last_cmd != "MAIL" {
                            return SmtpResult::err_bad_sequence();
                        }

                        rcpt.push(address);
                        SmtpResult::ok()
                    }
                    // RFC 5321, section 4.1.1.4
                    // DATA <CRLF>
                    "DATA" => {
                        // FIXME: Need to handle the error here.
                        let _ = w
                            .write_all(
                                &SmtpResult::new(
                                    SmtpStatus::START_MAIL_INPUT,
                                    "Start mail input; end with <CRLF>.<CRLF>",
                                )
                                .into_bytes(),
                            )
                            .await
                            .context("failed to write response");

                        let mut data = String::new();
                        loop {
                            let mut line = String::new();

                            // FIXME: Need to handle the error here.
                            let _ = bs.read_line(&mut line).await.context("failed to read line");
                            let l = line.strip_suffix("\r\n").unwrap_or(&line);

                            tracing::debug!("=> {l}");
                            if line == ".\r\n" {
                                break;
                            }

                            data.push_str(&line);
                        }

                        if let Some(message) = MessageParser::default().parse(&data) {
                            let subject = message.subject();
                            let mut attachments = Vec::new();

                            // Loop through each attachment and convert them to an ACS-compatible attachment.
                            for attachment in message.attachments() {
                                let name = if let Some(name) = attachment.attachment_name() {
                                    name.to_string()
                                } else {
                                    continue;
                                };
                                let ty = if let Some(ty) = attachment.content_type() {
                                    format!(
                                        "{}{}",
                                        ty.c_type,
                                        if let Some(sub) = &ty.c_subtype {
                                            format!("/{sub}")
                                        } else {
                                            format!("")
                                        }
                                    )
                                } else {
                                    continue;
                                };

                                attachments.push(acs::EmailAttachment {
                                    name: name,
                                    content_type: ty,
                                    content_in_base64: BASE64_STANDARD
                                        .encode(attachment.contents()),
                                    content_id: attachment.content_id().map(str::to_string),
                                })
                            }

                            let mail = acs::EmailMessage {
                                sender_address: send.as_deref().unwrap_or("noreply").to_string(),
                                content: acs::EmailContent {
                                    subject: subject.unwrap_or("").to_string(),
                                    html: message.body_html(0).map(|c| c.to_string()),
                                    plain_text: message.body_text(0).map(|c| c.to_string()),
                                },
                                recipients: acs::EmailRecipients {
                                    to: rcpt
                                        .clone()
                                        .into_iter()
                                        .map(|e| acs::EmailAddress {
                                            address: e,
                                            display_name: None,
                                        })
                                        .collect::<Vec<_>>(),
                                    cc: None,  // TODO
                                    bcc: None, // TODO
                                },
                                headers: None, // TODO
                                attachments: if attachments.len() != 0 {
                                    Some(attachments)
                                } else {
                                    None
                                },
                                reply_to: None, // TODO
                                user_engagement_tracking_disabled: None,
                            };

                            if let Ok(msg) = serde_json::to_string_pretty(&mail) {
                                tracing::debug!("{msg}");
                            }

                            send_mail(mail).await
                        } else {
                            // FIXME: Is this correct?
                            SmtpResult::new(
                                SmtpStatus::ERROR_PROCESSING,
                                format!("email does not conform to RFC 5322 format"),
                            )
                        }
                    }
                    // RFC 5321, section 4.1.1.5
                    // RSET <CRLF>
                    "RSET" => {
                        // Reset the internal buffers.
                        send = None;
                        rcpt = Vec::new();

                        SmtpResult::ok()
                    }
                    // NOOP [ SP String ] <CRLF>
                    "NOOP" => SmtpResult::ok(),
                    // QUIT <CRLF>
                    "QUIT" => SmtpResult::new(SmtpStatus::BYE, ""),
                    _ => SmtpResult::err_syntax(),
                }
            };

            let r = f.await;

            // Avoid recording `NOOP` as the last command.
            if cmd != "NOOP" {
                last_cmd = cmd.to_string();
            }

            r
        };

        tracing::debug!("<= {resp}");

        w.write_all(&resp.into_bytes())
            .await
            .context("failed to write response")?;

        if resp.code == SmtpStatus::BYE {
            break;
        }
    }

    Ok(())
}

async fn send_acs(
    config: AppConfig,
    token: Arc<dyn TokenCredential>,
    mail: acs::EmailMessage,
) -> SmtpResult {
    let r = (async || {
        let r = acs::send_email(&config.endpoint, mail, token.clone()).await?;
        acs::wait_email(&config.endpoint, r, token.clone()).await
    })()
    .await;

    match r {
        Err(e) => SmtpResult::new(SmtpStatus::ERROR_PROCESSING, format!("{e}")),
        Ok(r) => {
            match r.status {
                acs::EmailSendStatus::NotStarted | acs::EmailSendStatus::Running => {
                    // This should not be possible.
                    SmtpResult::new(
                        SmtpStatus::ERROR_PROCESSING,
                        format!("delivery returned non-terminal status {:?}", r.status),
                    )
                }
                acs::EmailSendStatus::Succeeded => {
                    SmtpResult::new(SmtpStatus::OK, format!("UUID {}", r.id))
                }
                acs::EmailSendStatus::Failed => SmtpResult::new(
                    SmtpStatus::ERROR_MAILBOX_UNAVAILABLE,
                    if let Some(err) = r.error {
                        format!(
                            "{} {}",
                            err.code.as_deref().unwrap_or("<unk>"),
                            err.message.as_deref().unwrap_or("<unk>"),
                        )
                    } else {
                        format!("delivery failed")
                    },
                ),
                acs::EmailSendStatus::Canceled => {
                    SmtpResult::new(SmtpStatus::ERROR_PROCESSING, format!("UUID {}", r.id))
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Set up trace logging to console and account for the user-provided verbosity flag.
    if args.verbosity.log_level_filter() != LevelFilter::Off {
        let lvl = match args.verbosity.log_level_filter() {
            LevelFilter::Off => tracing::Level::INFO,
            LevelFilter::Error => tracing::Level::ERROR,
            LevelFilter::Warn => tracing::Level::WARN,
            LevelFilter::Info => tracing::Level::INFO,
            LevelFilter::Debug => tracing::Level::DEBUG,
            LevelFilter::Trace => tracing::Level::TRACE,
        };
        tracing_subscriber::fmt().with_max_level(lvl).init();
    }

    // Read and parse the user-provided configuration.
    let config: AppConfig = Figment::new()
        .merge(figment::providers::Toml::file(args.config))
        .merge(figment::providers::Env::prefixed("ACSPROXY_"))
        .extract()
        .context("failed to load configuration")?;

    // Authenticate.
    //
    // N.B: We are _not_ going to add support for secret-based authentication.
    // It is insecure and strongly discouraged, so to encourage best practices
    // we should just not support it :)
    let token =
        azure_identity::create_default_credential().context("failed to create Azure credential")?;

    let listen_address =
        config
            .listen_address
            .unwrap_or(SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::LOCALHOST,
                5000,
            )));

    if !listen_address.ip().is_loopback() {
        anyhow::bail!("cannot listen on non-loopback address");
    }

    let listener = TcpListener::bind(listen_address)
        .await
        .context("failed to open port")?;

    eprintln!(
        "Server listening on {} with endpoint {}",
        listen_address, config.endpoint
    );

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((sock, _addr)) => {
                        let config = config.clone();
                        let token = token.clone();

                        // Hand the connection off to a new task.
                        tokio::spawn(handle_connection(
                            sock,
                            async move |message| {
                                send_acs(config.clone(), token.clone(), message).await
                            },
                        ));
                    }
                    Err(e) => {
                        tracing::error!("failed to accept connection: {}", e);
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                eprintln!("\nReceived Ctrl+C, shutting down gracefully...");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    async fn mock_send_ok(_message: acs::EmailMessage) -> SmtpResult {
        SmtpResult::ok()
    }

    /// Helper to read a line from a stream
    async fn read_line(stream: &mut TcpStream) -> SmtpResult {
        let mut buf = String::new();
        let mut rdr = BufReader::new(stream);

        rdr.read_line(&mut buf).await.unwrap();
        buf.parse().unwrap()
    }

    /// Helper to read a line and assert the status code matches expected
    async fn read_line_assert(stream: &mut TcpStream, expected_code: SmtpStatus) -> SmtpResult {
        let result = read_line(stream).await;
        assert_eq!(
            result.code, expected_code,
            "Expected status code {}, got {}. Message: {}",
            expected_code.0, result.code.0, result.mesg
        );
        result
    }

    /// Helper to write a command to the stream
    async fn write_command(stream: &mut TcpStream, cmd: &str) {
        stream.write_all(cmd.as_bytes()).await.unwrap();
        stream.write_all(b"\r\n").await.unwrap();
    }

    async fn write_command_expect(
        stream: &mut TcpStream,
        cmd: &str,
        expected: SmtpStatus,
    ) -> SmtpResult {
        write_command(stream, cmd).await;
        read_line_assert(stream, expected).await
    }

    #[test]
    fn test_smtp_result_into_bytes_single_line() {
        let result = SmtpResult::new(SmtpStatus::OK, "Success");
        let bytes = result.into_bytes();
        assert_eq!(bytes, b"250 Success\r\n");
    }

    #[test]
    fn test_smtp_result_into_bytes_multiline() {
        let result = SmtpResult::new(SmtpStatus::OK, "Line 1\nLine 2\nLine 3");
        let bytes = result.into_bytes();
        assert_eq!(bytes, b"250-Line 1\r\n250-Line 2\r\n250 Line 3\r\n");
    }

    #[test]
    fn test_smtp_result_into_bytes_multiline_two_lines() {
        let result = SmtpResult::new(SmtpStatus::OK, "First\nSecond");
        let bytes = result.into_bytes();
        assert_eq!(bytes, b"250-First\r\n250 Second\r\n");
    }

    #[test]
    fn test_smtp_result_into_bytes_bye() {
        let result = SmtpResult::new(SmtpStatus::BYE, "Goodbye");
        let bytes = result.into_bytes();
        assert_eq!(bytes, b"221 Goodbye\r\n");
    }

    #[test]
    fn test_smtp_result_into_bytes_empty_message() {
        let result = SmtpResult::new(SmtpStatus::OK, "");
        let bytes = result.into_bytes();
        assert_eq!(bytes, b"250 \r\n");
    }

    /// Test bad command sequences (e.g., MAIL before HELO, RCPT before MAIL)
    #[tokio::test]
    async fn test_smtp_bad_sequence() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, mock_send_ok).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        read_line_assert(&mut client, SmtpStatus::SERVICE_READY).await;

        // Try MAIL without HELO first
        write_command_expect(
            &mut client,
            "MAIL FROM:<sender@example.com>",
            SmtpStatus::ERROR_BAD_SEQUENCE,
        )
        .await;

        // Now do proper HELO
        write_command_expect(&mut client, "HELO client.example.com", SmtpStatus::OK).await;

        // Try RCPT without MAIL
        write_command_expect(
            &mut client,
            "RCPT TO:<recipient@example.com>",
            SmtpStatus::ERROR_BAD_SEQUENCE,
        )
        .await;

        write_command_expect(&mut client, "QUIT", SmtpStatus::BYE).await;

        drop(client);
        let _ = server.await;
    }

    /// Test syntax errors and unknown commands
    #[tokio::test]
    async fn test_smtp_syntax_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, mock_send_ok).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        read_line_assert(&mut client, SmtpStatus::SERVICE_READY).await;

        // Unknown command
        write_command_expect(&mut client, "INVALID", SmtpStatus::ERROR_SYNTAX).await;

        write_command_expect(&mut client, "HELO client.example.com", SmtpStatus::OK).await;

        // Invalid MAIL FROM syntax (missing angle brackets)
        write_command_expect(
            &mut client,
            "MAIL FROM:sender@example.com",
            SmtpStatus::ERROR_SYNTAX,
        )
        .await;

        write_command_expect(&mut client, "QUIT", SmtpStatus::BYE).await;

        drop(client);
        let _ = server.await;
    }

    /// Test RSET and NOOP commands
    #[tokio::test]
    async fn test_smtp_utility_commands() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, mock_send_ok).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        read_line_assert(&mut client, SmtpStatus::SERVICE_READY).await;

        // Test NOOP
        write_command_expect(&mut client, "NOOP", SmtpStatus::OK).await;

        // Start a transaction
        write_command_expect(&mut client, "HELO client.example.com", SmtpStatus::OK).await;
        write_command_expect(
            &mut client,
            "MAIL FROM:<sender@example.com>",
            SmtpStatus::OK,
        )
        .await;
        write_command_expect(
            &mut client,
            "RCPT TO:<recipient@example.com>",
            SmtpStatus::OK,
        )
        .await;

        // Reset transaction
        write_command_expect(&mut client, "RSET", SmtpStatus::OK).await;

        // Can start new transaction after RSET
        write_command_expect(&mut client, "HELO client.example.com", SmtpStatus::OK).await;
        write_command_expect(
            &mut client,
            "MAIL FROM:<sender2@example.com>",
            SmtpStatus::OK,
        )
        .await;

        write_command_expect(&mut client, "QUIT", SmtpStatus::BYE).await;

        drop(client);
        let _ = server.await;
    }

    /// Test the complete happy path: HELO -> MAIL -> RCPT -> DATA -> QUIT
    #[tokio::test]
    async fn test_smtp_happy_path() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, mock_send_ok).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();

        // Greeting
        read_line_assert(&mut client, SmtpStatus::SERVICE_READY).await;

        // HELO
        write_command_expect(&mut client, "HELO client.example.com", SmtpStatus::OK).await;

        // MAIL FROM
        write_command_expect(
            &mut client,
            "MAIL FROM:<sender@example.com>",
            SmtpStatus::OK,
        )
        .await;

        // RCPT TO
        write_command_expect(
            &mut client,
            "RCPT TO:<recipient@example.com>",
            SmtpStatus::OK,
        )
        .await;

        // QUIT
        write_command_expect(&mut client, "QUIT", SmtpStatus::BYE).await;

        drop(client);
        let _ = server.await;
    }

    /// Test sending an email with an attachment
    #[tokio::test]
    async fn test_smtp_with_attachment() {
        use std::sync::OnceLock;

        // Track the message sent to verify attachment is included
        let captured_message = Arc::new(OnceLock::new());
        let captured_clone = captured_message.clone();

        let mock_send_with_capture = async move |message: acs::EmailMessage| {
            captured_clone.set(message).unwrap();
            SmtpResult::ok()
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, mock_send_with_capture).await
        });

        let mut client = TcpStream::connect(addr).await.unwrap();
        read_line_assert(&mut client, SmtpStatus::SERVICE_READY).await;

        // HELO
        write_command_expect(&mut client, "HELO client.example.com", SmtpStatus::OK).await;

        // MAIL FROM
        write_command_expect(
            &mut client,
            "MAIL FROM:<sender@example.com>",
            SmtpStatus::OK,
        )
        .await;

        // RCPT TO
        write_command_expect(
            &mut client,
            "RCPT TO:<recipient@example.com>",
            SmtpStatus::OK,
        )
        .await;

        // DATA with MIME-encoded attachment
        write_command_expect(&mut client, "DATA", SmtpStatus::START_MAIL_INPUT).await;

        // Send a MIME message with attachment
        let mime_message = indoc::indoc! {"
            From: sender@example.com\r
            To: recipient@example.com\r
            Subject: Test with Attachment\r
            MIME-Version: 1.0\r
            Content-Type: multipart/mixed; boundary=\"boundary123\"\r
            \r
            --boundary123\r
            Content-Type: text/plain; charset=\"utf-8\"\r
            \r
            This is the email body with an attachment.\r
            \r
            --boundary123\r
            Content-Type: text/plain; name=\"test.txt\"\r
            Content-Transfer-Encoding: base64\r
            Content-Disposition: attachment; filename=\"test.txt\"\r
            Content-Id: <testfile>\r
            \r
            SGVsbG8sIFdvcmxkIQ==\r
            \r
            --boundary123--\r
        "};

        client.write_all(mime_message.as_bytes()).await.unwrap();

        // Should get OK response
        write_command_expect(&mut client, ".", SmtpStatus::OK).await;

        // QUIT
        write_command_expect(&mut client, "QUIT", SmtpStatus::BYE).await;

        drop(client);
        let _ = server.await;

        // Verify the captured message contains the expected data
        let msg = captured_message
            .get()
            .expect("message should have been captured");
        assert_eq!(msg.sender_address, "sender@example.com");
        assert_eq!(msg.content.subject, "Test with Attachment");
        assert_eq!(msg.recipients.to.len(), 1);
        assert_eq!(msg.recipients.to[0].address, "recipient@example.com");
        assert!(msg.content.plain_text.is_some());
        assert!(
            msg.content
                .plain_text
                .as_ref()
                .unwrap()
                .contains("This is the email body with an attachment")
        );
        // Verify attachment was parsed correctly
        assert!(msg.attachments.is_some());
        let attachments = msg.attachments.as_ref().unwrap();
        assert_eq!(attachments.len(), 1);
        assert_eq!(
            attachments[0],
            crate::acs::EmailAttachment {
                name: "test.txt".to_string(),
                content_type: "text/plain".to_string(),
                content_in_base64: "SGVsbG8sIFdvcmxkIQ==".to_string(),
                content_id: Some("testfile".to_string()),
            }
        );
    }
}
