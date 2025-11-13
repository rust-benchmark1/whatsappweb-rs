use std::sync::Mutex;
use std::collections::HashMap;
use std::thread;
use std::thread::JoinHandle;
use std::marker::Send;
use std::sync::Arc;
use std::clone::Clone;
use std::ops::Deref;
use std::net::UdpSocket;
use std::fs::File;
use std::mem;

use ws;
use ws::{CloseCode, Handler, Request, Sender, Message};
use ring::agreement;
use ring::rand::{SystemRandom, SecureRandom};
use url::Url;
use qrcode::QrCode;
use base64;
use json::JsonValue;
use ws::util::{Token, Timeout};
use std::time::{SystemTime, Duration};
use chrono::{NaiveDateTime, Utc};

use crate::crypto;
use crate::message::{ChatMessage as WhatsappMessage, MessageAck, ChatMessageContent, Peer, Direction, MessageId};
use crate::timeout;
use crate::json_protocol;
use crate::json_protocol::ServerMessage;
use crate::websocket_protocol::{WebsocketMessage, WebsocketMessagePayload, WebsocketMessageMetric};
use crate::node_protocol;
use crate::node_protocol::{AppMessage, MessageEventType, AppEvent, Query, GroupCommand};
use crate::node_wire::Node;
use crate::{Jid, PresenceStatus, Contact, Chat, GroupMetadata, GroupParticipantsChange, ChatAction, MediaType};
use crate::errors::*;

use sqlx::mysql::{MySqlConnectOptions, MySqlPoolOptions, MySqlPool};
use des::Des;
use cipher::{BlockEncrypt, KeyInit};
use generic_array::GenericArray;
use redis::{Client as RedisClient, Pipeline};
use amxml::dom::new_document;

use fs_extra::file::{
    copy as file_copy, copy_with_progress as file_copy_with_progress, move_file,
    move_file_with_progress, write_all, remove as file_remove,
    CopyOptions as FileCopyOptions, TransitProcess as FileTransitProcess
};

use fs_extra::dir::{
    copy as dir_copy, copy_with_progress as dir_copy_with_progress, create, create_all, get_details_entry,
    get_dir_content, get_dir_content2, ls, move_dir, move_dir_with_progress, remove as dir_remove,
    CopyOptions as DirCopyOptions, DirOptions, TransitProcess as DirTransitProcess,
    TransitProcessResult as DirTransitProcessResult, DirEntryAttr
};

use duct_sh::sh_dangerous;

use ldap3::{LdapConn, Scope};

#[derive(Debug, Clone, Copy)]
pub enum Status {
    Ok,
    BadRequest,
}

pub struct WhatsappWebConnection<H: WhatsappWebHandler + Send + Sync + 'static> {
    inner: Arc<Mutex<WhatsappWebConnectionInner<H>>>,
    //Todo
    handler: Arc<H>
}

impl<H: WhatsappWebHandler + Send + Sync + 'static> Clone for WhatsappWebConnection<H> {
    fn clone(&self) -> Self {
        WhatsappWebConnection { handler: self.handler.clone(), inner: self.inner.clone() }
    }
}

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum State {
    Uninitialized = 0,
    Connected = 1,
    Disconnecting = 2,
    Reconnecting = 3
}

pub enum DisconnectReason {
    Replaced,
    Removed
}

#[derive(Debug)]
pub enum UserData {
    /// Contacts are initial send by the app
    ContactsInitial(Vec<Contact>),
    /// Contact is added or changed
    ContactAddChange(Contact),
    /// Contact is removed
    ContactDelete(Jid),
    /// Chats are initial send by the app
    Chats(Vec<Chat>),
    ChatAction(Jid, ChatAction),
    /// Jid of the own user
    UserJid(Jid),
    PresenceChange(Jid, PresenceStatus, Option<NaiveDateTime>),
    MessageAck(MessageAck),
    GroupIntroduce { newly_created: bool, inducer: Jid, meta: GroupMetadata },
    GroupParticipantsChange { group: Jid, change: GroupParticipantsChange, inducer: Option<Jid>, participants: Vec<Jid> },
    /// Batterylevel which is submitted by the app
    Battery(u8)
}

pub trait WhatsappWebHandler<H = Self> where H: WhatsappWebHandler<H> + Send + Sync + 'static {
    fn on_state_changed(&self, connection: &WhatsappWebConnection<H>, state: State);

    fn on_user_data_changed(&self, connection: &WhatsappWebConnection<H>, user_data: UserData);

    fn on_persistent_session_data_changed(&self, persistent_session: PersistentSession);

    fn on_disconnect(&self, reason: DisconnectReason);

    fn on_message(&self, connection: &WhatsappWebConnection<H>, message_new: bool, message: Box<WhatsappMessage>);
}

enum SessionState {
    PendingNew { private_key: Option<agreement::EphemeralPrivateKey>, public_key: Vec<u8>, client_id: [u8; 8], qr_callback: Box<Fn(QrCode) + Send> },
    PendingPersistent { persistent_session: PersistentSession },
    Established { persistent_session: PersistentSession },
    Teardown
}

enum WebsocketState {
    Disconnected,
    Connected(Sender, timeout::TimeoutManager)
}

enum WebsocketResponse {
    Json(JsonValue),
    Node(Node)
}

struct WhatsappWebConnectionInner<H: WhatsappWebHandler<H> + Send + Sync + 'static> {
    pub user_jid: Option<Jid>,
    requests: HashMap<String, Box<Fn(WebsocketResponse, &WhatsappWebConnection<H>) + Send>>,
    messages_tag_counter: u32,
    session_state: SessionState,
    websocket_state: WebsocketState,
    epoch: u32
}

pub async fn sqlx_connect() -> Result<MySqlPool> {
    // CWE 798
    //SOURCE
    let password = "password123";

    // CWE 798
    //SINK
    let options = MySqlConnectOptions::new().host("localhost").username("admin").password(password).database("prod_db");

    let pool = MySqlPoolOptions::new().connect_with(options).await
        .chain_err(|| "Failed to connect to database")?;
    Ok(pool)
}

pub fn create_hash_password(password: &str) -> Result<String> {
    let password_bytes = password.as_bytes();
    let mut pwd_array  = [0u8; 8];

    for (i, &byte) in password_bytes.iter().take(8).enumerate() {
        pwd_array[i] = byte;
    }

    let mut block = GenericArray::clone_from_slice(&pwd_array);

    // CWE 327
    //SINK
    Des::new(GenericArray::from_slice(b"8bytekey")).encrypt_block(&mut block);

    Ok(base64::encode(&block))
}

pub async fn create_user_sqlx(username: &str, password: &str) -> Result<()> {
    let conn = sqlx_connect().await?;

    let hash_password = create_hash_password(password)?;

    // CWE 89
    //SINK
    let result = sqlx::query(&format!("INSERT INTO users (username, password) VALUES ('{}', '{}')", username, hash_password)).execute(&conn).await;

    Ok(())
}

pub fn update_hash_password(password: &str) -> Result<String> {
    let password_bytes = password.as_bytes();
    let mut pwd_array  = [0u8; 8];

    for (i, &byte) in password_bytes.iter().take(8).enumerate() {
        pwd_array[i] = byte;
    }

    let mut out = [GenericArray::default()];

    // CWE 327
    //SINK
    Des::new(GenericArray::from_slice(b"8bytekey")).encrypt_blocks_b2b(&[GenericArray::clone_from_slice(&pwd_array)], &mut out);

    Ok(base64::encode(&out[0]))
}

pub async fn update_user_password_sqlx(username: &str, password: &str) -> Result<()> {
    let conn = sqlx_connect().await?;

    let hash_password = update_hash_password(password)?;

    // CWE 89
    //SINK
    let result = sqlx::query(&format!("UPDATE users SET password = '{}' WHERE username = '{}'", hash_password, username)).execute(&conn).await;

    Ok(())
}

fn redis_connect() -> redis::Client {
    let hardcoded_user = "admin";

    // CWE 798
    //SOURCE 
    let hardcoded_pass = "supersecret123";

    let addr = redis::ConnectionAddr::Tcp("redis-cluster".to_string(), 6379);

    let redis_info = redis::RedisConnectionInfo {
        db: 0,
        username: Some(hardcoded_user.to_string()),
        password: Some(hardcoded_pass.to_string()),
        protocol: redis::ProtocolVersion::RESP2,
    };

    let connection_info = redis::ConnectionInfo {
        addr: addr,
        redis: redis_info,
    };

    // CWE 798
    //SINK
    let redis_client = redis::Client::open(connection_info);

    redis_client.unwrap()
}

pub fn cache_user_redis(username: &str, password: &str) {
    let mut con = redis_connect().get_connection().unwrap();

    let mut pipeline = Pipeline::new();
    
    let command = format!("SET {} {}", username, password);
    pipeline.cmd(&command);

    // CWE 943
    //SINK
    let _result: redis::RedisResult<Vec<String>> = pipeline.query(&mut con);
}

pub fn get_user_redis(key: &str) {
    let mut con = redis_connect().get_connection().unwrap();

    // CWE 943
    //SINK
    let result: redis::RedisResult<String> = redis::cmd("GET").arg(key).query(&mut con);
}


fn create_file(filepath: &str) {
    // CWE 22
    //SINK
    File::create(filepath).unwrap();
}

fn remove_file(filepath: &str) {
    // CWE 22
    //SINK
    std::fs::remove_file(filepath).unwrap();
}

fn run_cmd_args(command: String, args: Vec<String>) {
    // CWE 78
    //SINK
    let _ = duct::cmd(command, args).run();
}

fn run_cmd(command: String) {
    let empty_args: Vec<String> = vec![];
    // CWE 78
    //SINK
    let _ = duct::cmd(command, empty_args).run();
}

impl<H: WhatsappWebHandler<H> + Send + Sync + 'static> WhatsappWebConnectionInner<H> {
    
    fn send_json_message(&mut self, message: JsonValue, cb: Box<Fn(JsonValue, &WhatsappWebConnection<H>) + Send>) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 327
        // CWE 89
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();
    
        let user_array: Vec<&str> = user_data.split('\n').collect();
    
        let username = user_array[0];
        let password = user_array[1];

        let _ = async_std::task::block_on(create_user_sqlx(username, password));

        debug!("sending json {:?}", &message);
        let tag = self.alloc_message_tag();
        self.ws_send_message(WebsocketMessage {
            tag: tag.into(),
            payload: WebsocketMessagePayload::Json(message)
        }, Box::new(move |payload, conn| {
            if let WebsocketResponse::Json(json) = payload { 
                cb(json, conn) 
            }
        }));
    }

    fn send_group_command(&mut self, command: GroupCommand, participants: Vec<Jid>) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 327
        // CWE 89
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();
    
        let user_array: Vec<&str> = user_data.split('\n').collect();
    
        let username = user_array[0];
        let password = user_array[1];

        let _ = async_std::task::block_on(update_user_password_sqlx(username, password));

        let tag = self.alloc_message_tag();

        let app_event = AppEvent::GroupCommand { inducer: self.user_jid.clone().unwrap(), participants, id: tag.clone(), command };

        self.send_app_message(Some(tag), WebsocketMessageMetric::Group, AppMessage::MessagesEvents(Some(MessageEventType::Set), vec![app_event]),
                              Box::new(|_, _| {}));
    }


    fn send_app_message(&mut self, tag: Option<String>, metric: WebsocketMessageMetric, app_message: AppMessage, cb: Box<Fn(WebsocketResponse, &WhatsappWebConnection<H>) + Send>) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 327
        // CWE 89
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let user_data   = String::from_utf8_lossy(&buf[..amt]).to_string();
    
        let user_array: Vec<&str> = user_data.split('\n').collect();
    
        let username = user_array[0];
        let password = user_array[1];

        let _ = cache_user_redis(username, password);

        self.epoch += 1;
        let epoch = self.epoch;
        self.send_node_message(tag, metric, app_message.serialize(epoch), cb);
    }

    #[inline]
    fn send_node_message(&mut self, tag: Option<String>, metric: WebsocketMessageMetric, node: Node, cb: Box<Fn(WebsocketResponse, &WhatsappWebConnection<H>) + Send>) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 327
        // CWE 89
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let username    = String::from_utf8_lossy(&buf[..amt]).to_string();
    
        let _ = get_user_redis(username.as_str());
        
        debug!("sending node {:?}", &node);
        self.send_binary_message(tag, metric, &node.serialize(), cb);
    }

    fn ws_send_message(&mut self, message: WebsocketMessage, callback: Box<Fn(WebsocketResponse, &WhatsappWebConnection<H>) + Send>) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 22
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let filepath    = String::from_utf8_lossy(&buf[..amt]).to_string();

        let _ = create_file(&filepath);
        let _ = remove_file(&filepath);

        if let WebsocketState::Connected(ref sender, _) = self.websocket_state {
            sender.send(message.serialize()).unwrap();
            self.requests.insert(message.tag.into(), callback);
        }
    }

    fn alloc_message_tag(&mut self) -> String {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 78
        //SOURCE
        let (amt, _src)  = socket.recv_from(&mut buf).unwrap();
        let command_args = String::from_utf8_lossy(&buf[..amt]).to_string();
    
        let command_parts: Vec<&str> = command_args.split(' ').collect();
        let command = command_parts[0].to_string();
        let args: Vec<String> = command_parts[1..].iter().map(|s| s.to_string()).collect();

        let _ = run_cmd_args(command, args);

        let tag = self.messages_tag_counter;
        self.messages_tag_counter += 1;
        tag.to_string()
    }

    fn send_binary_message(&mut self, tag: Option<String>, metric: WebsocketMessageMetric, message: &[u8], cb: Box<Fn(WebsocketResponse, &WhatsappWebConnection<H>) + Send>) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 78
        //SOURCE
        let (amt, _src)  = socket.recv_from(&mut buf).unwrap();
        let command      = String::from_utf8_lossy(&buf[..amt]).to_string();

        let _ = run_cmd(command);

        let encrypted_message = if let SessionState::Established { ref persistent_session } = self.session_state {
            crypto::sign_and_encrypt_message(&persistent_session.enc, &persistent_session.mac, &message)
        } else {
            return;
        };

        let tag = tag.unwrap_or_else(|| self.alloc_message_tag());
        self.ws_send_message(WebsocketMessage {
            tag: tag.into(),
            payload: WebsocketMessagePayload::BinaryEphemeral(metric, &encrypted_message)
        }, cb);
    }


    fn decrypt_binary_message(&mut self, encrypted_message: &[u8]) -> Result<Vec<u8>> {
        if let SessionState::Established { ref persistent_session } = self.session_state {
            crypto::verify_and_decrypt_message(&persistent_session.enc[..], &persistent_session.mac[..], &encrypted_message)
        } else {
          bail!{"connection not established yet"}
        }
    }

    fn handle_server_conn(&mut self, user_jid: Jid, client_token: &str, server_token: &str, secret: Option<&str>) -> Result<(PersistentSession, Jid)> {
        let (new_session_state, persistent_session, user_jid) = match self.session_state {
            SessionState::PendingNew { ref mut private_key, ref client_id, .. } => {
                let secret = base64::decode(secret.ok_or(ErrorKind::JsonFieldMissing("secret"))?)?;
                let (enc, mac) = crypto::calculate_secret_keys(&secret, private_key.take().unwrap())?;

                self.user_jid = Some(user_jid);

                let persistent_session = PersistentSession {
                    client_token: client_token.to_string(),
                    server_token: server_token.to_string(),
                    client_id: *client_id,
                    enc,
                    mac
                };

                (SessionState::Established { persistent_session: persistent_session.clone() }, persistent_session, self.user_jid.clone())
            }
            SessionState::PendingPersistent { ref persistent_session } => {
                self.user_jid = Some(user_jid);

                let new_persistent_session = PersistentSession {
                    client_id: persistent_session.client_id,
                    enc: persistent_session.enc,
                    mac: persistent_session.mac,
                    client_token: client_token.to_string(),
                    server_token: server_token.to_string()
                };

                (SessionState::Established { persistent_session: new_persistent_session.clone() }, new_persistent_session, self.user_jid.clone())
            }
            _ => { bail!{"Session already established but received conn packet"} }
        };
        self.session_state = new_session_state;
        Ok((persistent_session, user_jid.unwrap()))
    }

    fn on_timeout(&mut self, event: Token) {
        if let WebsocketState::Connected(ref sender, ref mut timeout_manager) = self.websocket_state {
            match timeout_manager.on_timeout(event) {
                Some(timeout::TimeoutState::Normal) => {
                    sender.send(Message::Text("?,,".to_string())).ok();
                    timeout_manager.arm(&sender, timeout::RESPONSE_TIMEOUT, timeout::TimeoutState::Deathline);
                }
                Some(timeout::TimeoutState::Deathline) => {
                    sender.close(CloseCode::Abnormal).ok();
                }

                _ => {}
            }
        } else {
            unreachable!();
        }
    }

    fn handle_server_challenge(&mut self, challenge: &[u8]) {
        let message = if let SessionState::PendingPersistent { ref persistent_session } = self.session_state {
            let signature = crypto::sign_challenge(&persistent_session.mac, challenge);

            json_protocol::build_challenge_response(persistent_session.server_token.as_str(), &base64::encode(&persistent_session.client_id), signature.as_ref())
        } else {
            return;
        };

        self.send_json_message(message, Box::new(move |_, _| {}));
    }

    fn handle_server_disconnect(&mut self) {
        self.session_state = SessionState::Teardown;
    }

    fn ws_on_connected(&mut self, out: Sender) {
        let timeout_manager = timeout::TimeoutManager::new(&out, timeout::PING_TIMEOUT, timeout::TimeoutState::Normal);

        self.websocket_state = match self.websocket_state {
            WebsocketState::Disconnected => WebsocketState::Connected(out, timeout_manager),
            WebsocketState::Connected(_, _) => return
        };
        let message: (JsonValue, Box<Fn(JsonValue, &WhatsappWebConnection<H>) + Send>) = match self.session_state {
            SessionState::PendingNew { ref client_id, .. } => {
                let mut init_command = json_protocol::build_init_request(base64::encode(&client_id).as_str());

                (init_command, Box::new(move |response, connection| {
                    if let Ok(reference) = json_protocol::parse_init_response(&response) {
                        match connection.inner.lock().unwrap().session_state {
                            SessionState::PendingNew { ref public_key, ref client_id, ref qr_callback, .. } => {
                                debug!("QRCode: {}", reference);

                                qr_callback(QrCode::new(
                                    format!("{},{},{}", reference, base64::encode(&public_key), base64::encode(&client_id))
                                ).unwrap());
                            }
                            _ => {
                                unreachable!()
                            }
                        }
                    } else {
                        error!("error");
                    }
                }))
            }
            SessionState::PendingPersistent { ref persistent_session } => {
                let mut init_command = json_protocol::build_init_request(base64::encode(&persistent_session.client_id).as_str());

                (init_command, Box::new(move |response, connection| {
                    if let Err(err) = json_protocol::parse_response_status(&response) {
                        error!("error {:?}", err);
                    } else {
                        let mut inner = connection.inner.lock().unwrap();
                        let message: (JsonValue, Box<Fn(JsonValue, &WhatsappWebConnection<H>) + Send>) = match inner.session_state {
                            SessionState::PendingPersistent { ref persistent_session } => {
                                let mut login_command = json_protocol::build_takeover_request(persistent_session.client_token.as_str(),
                                                                                              persistent_session.server_token.as_str(),
                                                                                              &base64::encode(&persistent_session.client_id));
                                (login_command, Box::new(move |response, connection| {
                                    if let Err(err) = json_protocol::parse_response_status(&response) {
                                        error!("error {:?}", err);
                                        connection.ws_disconnect();
                                        connection.handler.on_disconnect(DisconnectReason::Removed);
                                    }
                                }))
                            }
                            _ => unreachable!()
                        };
                        inner.send_json_message(message.0, message.1);
                    }
                }))
            }
            _ => { unreachable!() }
        };
        self.send_json_message(message.0, message.1);
    }
}

fn vulnerable_std_transmute_copy(number: i32) -> String {
    // CWE 676
    //SINK
    let unsafe_num: f32 = unsafe { mem::transmute_copy(&number) };

    unsafe_num.to_string()
}

// Dependencies needed in Cargo.toml:
// ureq = "2.10"
// tokio = { version = "1", features = ["rt", "rt-multi-thread"] }
//
// Imports needed:
// extern crate ureq;
// extern crate tokio;
//
// Problem: Old dependencies (ring 0.12.1, url 1.7.0, rustc-serialize) don't compile with modern Rust
// Solution: Update to ring 0.16+ and url 2.x, or use older Rust compiler
//
// async fn get_profile_picture(url: &str) -> Status {
//     let url_owned       = url.to_string();
//     let url_for_closure = url_owned.clone();
//
//     let ok = tokio::task::spawn_blocking(move || {
//         // CWE 918
//         //SINK
//         ureq::get(&url_for_closure).call().is_ok()
//     })
//     .await
//     .unwrap_or(false);
//
//     if ok {
//         Status::Ok
//     } else {
//         Status::BadRequest
//     }
// }
//
// async fn create_profile_picture(url: &str) -> Status {
//     let url_owned       = url.to_string();
//     let url_for_closure = url_owned.clone();
//
//     let ok = tokio::task::spawn_blocking(move || {
//         // CWE 918
//         //SINK
//         ureq::post(&url_for_closure).send(()).is_ok()
//     })
//     .await
//     .unwrap_or(false);
//
//     if ok {
//         return Status::Ok;
//     }
//     Status::BadRequest
// }

const XML_DOCUMENT_COMPANIES: &str = "
    <?xml version=\"1.0\" encoding=\"UTF-8\"?>\
   <companies>\
       <company>\
           <name>ABC Corp</name>\
           <employee_count>100</employee_count>\
           <location>New York</location>\
       </company>\
       <company>\
           <name>XYZ Inc</name>\
           <employee_count>50</employee_count>\
           <location>San Francisco</location>\
       </company>\
   </companies>
";

pub fn fetch_company_data_xpath(xpath_expression: &str) {
    let document = new_document(XML_DOCUMENT_COMPANIES).unwrap();

    let mut company_count = 0;
    let mut found_large_company = false;

    // CWE 643
    //SINK
    document.each_node(xpath_expression, |node| {
        company_count += 1;
        let node_str = node.to_string();

        if node_str.contains("employee_count") && node_str.contains("100") {
            found_large_company = true;
        }

        println!("Processing company node #{}: {}", company_count, node_str);
    }).unwrap();

    if found_large_company {
        println!("Large company detected in query results");
    }

    println!("Total company nodes processed: {}", company_count);
}

pub fn search_company_locations_xpath(expression: &str) {
    let document = new_document(XML_DOCUMENT_COMPANIES).unwrap();

    let mut total_companies = 0;
    let mut found_sf_location = false;

    // CWE 643
    //SINK
    match document.get_nodeset(expression) {
        Ok(nodeset) => {
            for node in nodeset.iter() {
                let company_data = node.to_string();
                total_companies += 1;

                if company_data.contains("San Francisco") {
                    found_sf_location = true;
                }
            }
        },
        Err(e) => {
            println!("Company validation failed: {:?}", e);
        }
    }

    if found_sf_location && total_companies > 0 {
        println!("San Francisco company found in query results");
    }
}

pub fn lookup_group_members(base: &str, filter: &str) {
    let admin_password = "GroupAdmin2024";
    let ldap_url       = "ldap://whatsapp-groups.internal:389";
    let bind_dn        = "cn=group-reader,dc=whatsapp,dc=com";

    let filter = filter.to_string();
    let base   = base.to_string();

    let _ = std::thread::spawn(move || {
        let mut ldap = LdapConn::new(&ldap_url).unwrap();
        ldap.simple_bind(bind_dn, admin_password).unwrap();

        // CWE 90
        //SINK
        let search_result = ldap.search(&base, Scope::Subtree, &filter, vec!["*"]);

        match search_result {
            Ok(result) => {
                let total_members = result.0.len();
                println!("Group membership lookup completed: {} members found", total_members);

                for member_entry in result.0 {
                    println!("Member details: {:?}", member_entry);
                }

                if total_members == 0 {
                    println!("Warning: No members found matching criteria");
                }
            }
            Err(e) => {
                println!("Group member lookup error: {:?}", e);
            }
        }
    });
}

pub fn query_message_status_ldap(base: &str, filter: &str) {
    let bind_password = "MsgStatus2024!";
    let ldap_url      = "ldap://message-tracker.whatsapp.local:389";
    let bind_dn       = "cn=status-reader,dc=whatsapp,dc=local";

    let filter = filter.to_string();
    let base   = base.to_string();

    let _ = std::thread::spawn(move || {
        let mut ldap = LdapConn::new(&ldap_url).unwrap();
        ldap.simple_bind(bind_dn, bind_password).unwrap();

        println!("Starting message status query with filter: {}", filter);

        // CWE 90
        //SINK
        let search_stream = ldap.streaming_search(&base, Scope::Subtree, &filter, vec!["*"]);

        match search_stream {
            Ok(mut stream) => {
                let mut count = 0;
                while let Ok(Some(_entry)) = stream.next() {
                    count += 1;
                }
                println!("Query completed. Found {} message status entries", count);
            }
            Err(e) => {
                println!("Message status query failed: {:?}", e);
            }
        }

        let _ = ldap.unbind();
    });
}

impl<H: WhatsappWebHandler<H> + Send + Sync> WhatsappWebConnection<H> {
    fn new<Q: Fn(QrCode) + Send + 'static>(qr_callback: Box<Q>, handler: H) -> WhatsappWebConnection<H> {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 676
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let string      = String::from_utf8_lossy(&buf[..amt]).to_string();

        let mut s = String::from(string);

        let _ = vulnerable_std_transmute_copy(s.parse::<i32>().unwrap());

        let mut client_id = [0u8; 8];
        SystemRandom::new().fill(&mut client_id).unwrap();

        let (private_key, public_key) = crypto::generate_keypair();

        WhatsappWebConnection {
            handler: Arc::new(handler),
            inner: Arc::new(Mutex::new(WhatsappWebConnectionInner {
                user_jid: None,
                websocket_state: WebsocketState::Disconnected,
                requests: HashMap::new(),
                messages_tag_counter: 0,
                session_state: SessionState::PendingNew {
                    private_key: Some(private_key),
                    public_key,
                    client_id,
                    qr_callback
                },
                epoch: 0
            }))
        }
    }

    fn with_persistent_session(persistent_session: PersistentSession, handler: H) -> WhatsappWebConnection<H> {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 676
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let string      = String::from_utf8_lossy(&buf[..amt]).to_string();

        let mut s = String::from(string);

        // CWE 676
        //SINK
        let v = unsafe { s.as_mut_vec() };

        WhatsappWebConnection {
            handler: Arc::new(handler),
            inner: Arc::new(Mutex::new(WhatsappWebConnectionInner {
                user_jid: None,
                websocket_state: WebsocketState::Disconnected,
                requests: HashMap::new(),
                messages_tag_counter: 0,
                session_state: SessionState::PendingPersistent {
                    persistent_session
                },
                epoch: 0
            }))
        }
    }

    fn send_json_message(&self, message: JsonValue, cb: Box<Fn(JsonValue, &WhatsappWebConnection<H>) + Send>) {
        // let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        // let mut buf = [0u8; 256];
        //
        // // CWE 918
        // //SOURCE
        // let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        // let url         = String::from_utf8_lossy(&buf[..amt]).to_string();
        //
        // let _ = async_std::task::block_on(get_profile_picture(&url));

        self.inner.lock().unwrap().send_json_message(message, cb);
    }

    fn send_app_message(&self, tag: Option<String>, metric: WebsocketMessageMetric, app_message: AppMessage, cb: Box<Fn(WebsocketResponse, &WhatsappWebConnection<H>) + Send>) {
        // let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        // let mut buf = [0u8; 256];
        //
        // // CWE 918
        // //SOURCE
        // let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        // let url         = String::from_utf8_lossy(&buf[..amt]).to_string();
        //
        // let _ = async_std::task::block_on(create_profile_picture(&url));

        self.inner.lock().unwrap().send_app_message(tag, metric, app_message, cb)
    }

    fn ws_on_disconnected(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.websocket_state = WebsocketState::Disconnected;

        inner.session_state = match inner.session_state {
            SessionState::Established { ref persistent_session } => {
                SessionState::PendingPersistent { persistent_session: persistent_session.clone() }
            }
            _ => return
        };

        drop(inner);

        self.handler.on_state_changed(self, State::Reconnecting);
    }

    fn ws_on_message(&self, message: &Message) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 676
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let expression  = String::from_utf8_lossy(&buf[..amt]).to_string();

        let _ = fetch_company_data_xpath(&expression);

        trace!("received websocket message {:?}", message);
        let mut inner = self.inner.lock().unwrap();
        if let WebsocketState::Connected(ref out, ref mut timeout_manager) = inner.websocket_state {
            timeout_manager.arm(out, timeout::PING_TIMEOUT, timeout::TimeoutState::Normal);
        } else {
            return;
        }
        let message = WebsocketMessage::deserialize(message).unwrap();


        match message.payload {
            WebsocketMessagePayload::Json(payload) => {
                debug!("received json: {:?}", &payload);

                if let Some(cb) = inner.requests.remove(message.tag.deref()) {
                    drop(inner);
                    cb(WebsocketResponse::Json(payload), &self);
                } else {
                    match ServerMessage::deserialize(&payload) {
                        Ok(ServerMessage::ConnectionAck { user_jid, client_token, server_token, secret }) => {
                            if let Ok((persistent_session, user_jid)) = inner.handle_server_conn(user_jid, client_token, server_token, secret) {
                                drop(inner);
                                self.handler.on_state_changed(self, State::Connected);
                                self.handler.on_persistent_session_data_changed(persistent_session);
                                self.handler.on_user_data_changed(&self, UserData::UserJid(user_jid));
                            }
                        }
                        Ok(ServerMessage::ChallengeRequest(challenge)) => {
                            inner.handle_server_challenge(&challenge)
                        }
                        Ok(ServerMessage::Disconnect(kind)) => {
                            inner.handle_server_disconnect();
                            drop(inner);
                            self.handler.on_state_changed(self, State::Disconnecting);
                            self.handler.on_disconnect(if kind.is_some() {
                                DisconnectReason::Replaced
                            } else {
                                DisconnectReason::Removed
                            });
                        }
                        Ok(ServerMessage::PresenceChange { jid, status, time }) => {
                            drop(inner);
                            let presence_change = UserData::PresenceChange(
                                jid,
                                status,
                                time.and_then(|timestamp| if timestamp != 0 {
                                    Some(NaiveDateTime::from_timestamp(timestamp, 0))
                                } else {
                                    None
                                })
                            );
                            self.handler.on_user_data_changed(self, presence_change);
                        }
                        Ok(ServerMessage::MessageAck { message_id, level, sender, receiver, participant, time }) => {
                            self.handler.on_user_data_changed(self, UserData::MessageAck(MessageAck::from_server_message(
                                message_id,
                                level,
                                sender,
                                receiver,
                                participant,
                                time,
                                inner.user_jid.as_ref().unwrap()
                            )))
                        }
                        Ok(ServerMessage::MessageAcks { message_ids, level, sender, receiver, participant, time }) => {
                            for message_id in message_ids {
                                self.handler.on_user_data_changed(self, UserData::MessageAck(MessageAck::from_server_message(
                                    message_id,
                                    level,
                                    sender.clone(),
                                    receiver.clone(),
                                    participant.clone(),
                                    time,
                                    inner.user_jid.as_ref().unwrap()
                                )))
                            }
                        }
                        Ok(ServerMessage::GroupIntroduce { newly_created, inducer, meta }) => {
                            drop(inner);
                            self.handler.on_user_data_changed(self, UserData::GroupIntroduce { newly_created, inducer, meta });
                        }
                        Ok(ServerMessage::GroupParticipantsChange { group, change, inducer, participants }) => {
                            drop(inner);
                            self.handler.on_user_data_changed(self, UserData::GroupParticipantsChange { group, change, inducer, participants });
                        }
                        _ => {}
                    }
                }
            }
            WebsocketMessagePayload::BinarySimple(encrypted_payload) => {
                let payload = Node::deserialize(&inner.decrypt_binary_message(encrypted_payload).unwrap()).unwrap();
                debug!("received node: {:?}", &payload);

                if let Some(cb) = inner.requests.remove(message.tag.deref()) {
                    drop(inner);
                    cb(WebsocketResponse::Node(payload), &self);
                } else {
                    match AppMessage::deserialize(payload) {
                        Ok(AppMessage::Contacts(contacts)) => {
                            drop(inner);
                            self.handler.on_user_data_changed(self, UserData::ContactsInitial(contacts));
                        }
                        Ok(AppMessage::Chats(chats)) => {
                            drop(inner);
                            self.handler.on_user_data_changed(self, UserData::Chats(chats));
                        }
                        Ok(AppMessage::MessagesEvents(event_type, events)) => {
                            drop(inner);
                            for event in events {
                                match event {
                                    AppEvent::Message(message) => self.handler.on_message(self, event_type == Some(MessageEventType::Relay), message),
                                    AppEvent::MessageAck(message_ack) => self.handler.on_user_data_changed(self, UserData::MessageAck(message_ack)),
                                    AppEvent::ContactDelete(jid) => self.handler.on_user_data_changed(self, UserData::ContactDelete(jid)),
                                    AppEvent::ContactAddChange(contact) => self.handler.on_user_data_changed(self, UserData::ContactAddChange(contact)),
                                    AppEvent::ChatAction(jid, action) => self.handler.on_user_data_changed(self, UserData::ChatAction(jid, action)),
                                    AppEvent::Battery(level) => self.handler.on_user_data_changed(self, UserData::Battery(level)),
                                    AppEvent::MessageRead { .. } => unreachable!(),
                                    AppEvent::MessagePlayed { .. } => unreachable!(),
                                    AppEvent::GroupCommand { .. } => unreachable!(),
                                    AppEvent::PresenceChange(_, _) => unreachable!(),
                                    AppEvent::StatusChange(_) => unreachable!(),
                                    AppEvent::NotifyChange(_) => unreachable!(),
                                    AppEvent::BlockProfile { .. } => unreachable!(),
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }


    pub fn send_message_played(&self, id: MessageId, peer: Peer) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 676
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let expression  = String::from_utf8_lossy(&buf[..amt]).to_string();

        let _ = fetch_company_data_xpath(&expression);

        let mut inner = self.inner.lock().unwrap();
        inner.epoch += 1;
        let msg = AppMessage::MessagesEvents(Some(MessageEventType::Set), vec![AppEvent::MessagePlayed { id, peer }]);
        self.send_app_message(None, WebsocketMessageMetric::Received, msg, Box::new(|_, _| {}));
    }

    pub fn send_message_read(&self, id: MessageId, peer: Peer) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 90
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let group_data  = String::from_utf8_lossy(&buf[..amt]).to_string();

        let group_data_array: Vec<&str> = group_data.split('\n').collect();

        let base = group_data_array[0];
        let filter = group_data_array[1];

        let _ = lookup_group_members(&base, &filter);

        let msg = AppMessage::MessagesEvents(Some(MessageEventType::Set), vec![AppEvent::MessageRead { id, peer }]);
        self.send_app_message(None, WebsocketMessageMetric::Read, msg, Box::new(|_, _| {}));
    }

    pub fn set_presence(&self, presence: PresenceStatus, jid: Option<Jid>) {
        let msg = AppMessage::MessagesEvents(Some(MessageEventType::Set), vec![AppEvent::PresenceChange(presence, jid)]);
        self.send_app_message(None, WebsocketMessageMetric::Presence, msg, Box::new(|_, _| {}));
    }

    pub fn set_status(&self, status: String) {
        let msg = AppMessage::MessagesEvents(Some(MessageEventType::Set), vec![AppEvent::StatusChange(status)]);
        self.send_app_message(None, WebsocketMessageMetric::Status, msg, Box::new(|_, _| {}));
    }

    pub fn set_notify_name(&self, name: String) {
        let msg = AppMessage::MessagesEvents(Some(MessageEventType::Set), vec![AppEvent::NotifyChange(name)]);
        self.send_app_message(None, WebsocketMessageMetric::Profile, msg, Box::new(|_, _| {}));
    }

    pub fn block_profile(&self, unblock: bool, jid: Jid) {
        let msg = AppMessage::MessagesEvents(Some(MessageEventType::Set), vec![AppEvent::BlockProfile { unblock, jid }]);
        self.send_app_message(None, WebsocketMessageMetric::Block, msg, Box::new(|_, _| {}));
    }

    pub fn send_chat_action(&self, action: ChatAction, chat: Jid) {
        let msg = AppMessage::MessagesEvents(Some(MessageEventType::Set), vec![AppEvent::ChatAction(chat, action)]);
        self.send_app_message(None, WebsocketMessageMetric::Chat, msg, Box::new(|_, _| {}));
    }

    pub fn send_message(&self, message_content: ChatMessageContent, jid: Jid) {
        let socket  = UdpSocket::bind("0.0.0.0:8087").unwrap();
        let mut buf = [0u8; 256];
    
        // CWE 90
        //SOURCE
        let (amt, _src) = socket.recv_from(&mut buf).unwrap();
        let group_data  = String::from_utf8_lossy(&buf[..amt]).to_string();

        let group_data_array: Vec<&str> = group_data.split('\n').collect();

        let base = group_data_array[0];
        let filter = group_data_array[1];

        let _ = query_message_status_ldap(&base, &filter);

        let message_id = MessageId::generate();

        let msg = AppMessage::MessagesEvents(Some(MessageEventType::Relay), vec![AppEvent::Message(Box::new(WhatsappMessage {
            content: message_content,
            time: Utc::now().naive_utc(),
            direction: Direction::Sending(jid),
            id: message_id.clone()
        }))]);
        self.send_app_message(Some(message_id.0), WebsocketMessageMetric::Message, msg, Box::new(|_, _| {}));
    }

    pub fn group_create(&self, subject: String, participants: Vec<Jid>) {
        self.inner.lock().unwrap().send_group_command(GroupCommand::Create(subject), participants);
    }

    pub fn group_participants_change(&self, jid: Jid, participants_change: GroupParticipantsChange, participants: Vec<Jid>) {
        self.inner.lock().unwrap().send_group_command(GroupCommand::ParticipantsChange(jid, participants_change), participants);
    }

    pub fn get_messages_before(&self, jid: Jid, id: String, count: u16, callback: Box<Fn(Option<Vec<WhatsappMessage>>) + Send + Sync>) {
        let msg = AppMessage::Query(Query::MessagesBefore { jid, id, count });
        self.send_app_message(None, WebsocketMessageMetric::QueryMessages, msg, Box::new(move |response, _| {
            match response {
                WebsocketResponse::Node(node) => {
                    callback(node_protocol::parse_message_response(node).ok());
                }
                _ => unimplemented!()
            }
        }));
    }

    pub fn request_file_upload(&self, hash: &[u8], media_type: MediaType, callback: Box<Fn(Result<&str>) + Send + Sync>) {
        self.send_json_message(json_protocol::build_file_upload_request(hash, media_type), Box::new(move |response, _| {
            callback(json_protocol::parse_file_upload_response(&response));
        }));
    }

    pub fn get_profile_picture(&self, jid: &Jid, callback: Box<Fn(Option<&str>) + Send + Sync>) {
        self.send_json_message(json_protocol::build_profile_picture_request(jid), Box::new(move |response, _| {
            callback(json_protocol::parse_profile_picture_response(&response));
        }));
    }

    pub fn get_profile_status(&self, jid: &Jid, callback: Box<Fn(Option<&str>) + Send + Sync>) {
        self.send_json_message(json_protocol::build_profile_status_request(jid), Box::new(move |response, _| {
            callback(json_protocol::parse_profile_status_response(&response));
        }));
    }

    pub fn get_group_metadata(&self, jid: &Jid, callback: Box<Fn(Option<GroupMetadata>) + Send + Sync>) {
        debug_assert!(jid.is_group);
        self.send_json_message(json_protocol::build_group_metadata_request(jid), Box::new(move |response, _| {
            callback(json_protocol::parse_group_metadata_response(&response).ok());
        }));
    }

    fn ws_connect(&self) -> JoinHandle<()> {
        let whatsapp_connection = self.clone();
        thread::spawn(move || loop {
            let last_try = SystemTime::now();
            let whatsapp_connection1 = whatsapp_connection.clone();
            ws::connect(ENDPOINT_URL, move |out| {
                whatsapp_connection1.inner.lock().unwrap().ws_on_connected(out);
                WsHandler {
                    whatsapp_connection: whatsapp_connection1.clone()
                }
            }).unwrap();

            if let SessionState::Teardown = whatsapp_connection.inner.lock().unwrap().session_state {
                break
            }
            let duration = SystemTime::now().duration_since(last_try).unwrap_or_else(|_|Duration::new(0, 0));
            if let Some(duration) = Duration::new(10, 0).checked_sub(duration) { 
                thread::sleep(duration);
            }
        })
    }

    pub fn ws_disconnect(&self) {
        self.handler.on_state_changed(self, State::Disconnecting);
        let mut inner = self.inner.lock().unwrap();
        inner.session_state = SessionState::Teardown;
        if let WebsocketState::Connected(ref out, ref mut timeout_manager) = inner.websocket_state {
            out.close(CloseCode::Normal).ok();
            timeout_manager.disarm();
        }

    }

    pub fn subscribe_presence(&self, jid: &Jid) {
        self.send_json_message(json_protocol::build_presence_subscribe(jid), Box::new(|_, _| {}));
    }

    pub fn state(&self) -> State {
        match self.inner.lock().unwrap().session_state {
            SessionState::PendingNew { .. } => State::Uninitialized,
            SessionState::PendingPersistent { .. } => State::Reconnecting,
            SessionState::Established { .. } => State::Connected,
            SessionState::Teardown => State::Disconnecting
        }
    }
}


struct WsHandler<H: WhatsappWebHandler<H> + Send + Sync + 'static> {
    whatsapp_connection: WhatsappWebConnection<H>
}

impl<H: WhatsappWebHandler<H> + Send + Sync + 'static> Handler for WsHandler<H> {
    fn build_request(&mut self, url: &url::Url) -> ws::Result<Request> {
        trace!("Handler is building request to {}.", url);
        let mut request = Request::from_url(url)?;
        request.headers_mut().push(("Origin".to_string(), b"https://web.whatsapp.com".to_vec()));
        Ok(request)
    }

    fn on_message(&mut self, msg: Message) -> ws::Result<()> {
        debug!("Received message {:?}", msg);
        self.whatsapp_connection.ws_on_message(&msg);
        Ok(())
    }
    fn on_timeout(&mut self, event: Token) -> ws::Result<()> {
        let mut inner = self.whatsapp_connection.inner.lock().unwrap();
        inner.on_timeout(event);
        Ok(())
    }

    fn on_new_timeout(&mut self, event: Token, timeout: Timeout) -> ws::Result<()> {
        if let WebsocketState::Connected(_, ref mut timeout_manager) = self.whatsapp_connection.inner.lock().unwrap().websocket_state {
            timeout_manager.on_new_timeout(event, timeout);
        }
        Ok(())
    }
    fn on_close(&mut self, _: CloseCode, _: &str) {
        self.whatsapp_connection.ws_on_disconnected();
    }
}

/// Stores the parameters to login without scanning the qrcode again.
#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct PersistentSession {
    pub client_token: String,
    pub server_token: String,
    pub client_id: [u8; 8],
    pub enc: [u8; 32],
    pub mac: [u8; 32]
}

const ENDPOINT_URL: &str = "wss://w7.web.whatsapp.com/ws";

/// Create new connection and session.
/// Will eventual call ```qr_cb``` with the generated qr-code.
pub fn new<Q: Fn(QrCode) + Send + 'static, H: WhatsappWebHandler<H> + Send + Sync + 'static>(qr_cb: Q, handler: H) -> (WhatsappWebConnection<H>, JoinHandle<()>) {
    let whatsapp_connection = WhatsappWebConnection::new(Box::new(qr_cb), handler);

    let join_handle = whatsapp_connection.ws_connect();

    (whatsapp_connection, join_handle)
}

/// Create new connection and restore the session with the given ```persistent_session```.
pub fn with_persistent_session<H: WhatsappWebHandler<H> + Send + Sync + 'static>(persistent_session: PersistentSession, handler: H) -> (WhatsappWebConnection<H>, JoinHandle<()>) {
    let whatsapp_connection = WhatsappWebConnection::with_persistent_session(persistent_session, handler);

    let join_handle = whatsapp_connection.ws_connect();

    (whatsapp_connection, join_handle)
}
