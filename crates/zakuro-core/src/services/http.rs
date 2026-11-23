//! http:C, the guest HTTP client used by NASC and Nintendo Network.
//!
//! Requests execute on host worker threads: an HTTP round trip must never
//! block the emulator's instruction or IPC thread. The implementation uses
//! the host curl executable for HTTP/TLS and only exposes the guest IPC
//! subset needed for ordinary GET/POST flows.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use crate::kernel::ipc::{CommandBuffer, Descriptor, Header};
use crate::{NetworkProvider, System};

const MAX_URL: usize = 8192;
const MAX_HEADER: usize = 8192;
const MAX_BODY: usize = 16 * 1024 * 1024;
const HTTP_GET: u32 = 1;
const HTTP_POST: u32 = 2;
const HTTP_HEAD: u32 = 3;
const HTTP_PUT: u32 = 4;
const HTTP_DELETE: u32 = 5;
const HTTP_POST_EMPTY: u32 = 6;
const HTTP_PUT_EMPTY: u32 = 7;
const STATE_NOT_STARTED: u32 = 1;
const STATE_CONNECTING: u32 = 5;
const STATE_RECEIVED: u32 = 9;
const STATE_COMPLETED: u32 = 10;
const CLIENT_CERT_DEFAULT: u32 = 0x40;
const ERROR_HEADER_NOT_FOUND: u32 = 0xD8A0_A028;
const ERROR_HTTP_STATE: u32 = 0xD8A0_A066;
const ERROR_TIMEOUT: u32 = 0xD820_A069;
const HTTP_RESPONSE_WAIT: Duration = Duration::from_secs(36);
static NEXT_REQUEST_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone)]
struct HttpResponse {
    status: u32,
    version: String,
    reason: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

#[derive(Clone)]
struct HttpRequest {
    url: String,
    method: u32,
    headers: Vec<(String, String)>,
    post_fields: Vec<(String, Vec<u8>)>,
    raw_body: Option<Vec<u8>>,
    force_multipart: bool,
    post_data_encoding: u32,
    chunked_request: bool,
    post_data_type: u32,
    post_data_added: bool,
    post_pending_request: bool,
    use_client_certificate: bool,
}

struct HttpContext {
    request: HttpRequest,
    state: u32,
    response: Option<HttpResponse>,
    receiver: Option<Receiver<Result<HttpResponse, String>>>,
    error: Option<String>,
    body_offset: usize,
}

impl HttpContext {
    fn finish(&mut self, result: Result<HttpResponse, String>) {
        self.receiver = None;
        match result {
            Ok(response) => {
                self.response = Some(response);
                self.state = STATE_RECEIVED;
            }
            Err(error) => {
                log::warn!("http:C request failed: {error}");
                self.error = Some(error);
                self.state = STATE_COMPLETED;
            }
        }
    }

    fn refresh(&mut self) {
        let result = self.receiver.as_ref().and_then(|receiver| match receiver.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("HTTP worker stopped before returning a response".to_owned())),
            Err(mpsc::TryRecvError::Empty) => None,
        });
        if let Some(result) = result {
            self.finish(result);
        }
    }

    /// Wait for response headers as the synchronous HTTP:C response commands
    /// do. A timed-out call restores the receiver so a later call can retry.
    fn wait_for_response(&mut self, timeout: Option<Duration>) -> bool {
        self.refresh();
        if self.response.is_some() {
            return true;
        }
        if self.error.is_some() {
            return false;
        }
        let Some(receiver) = self.receiver.take() else {
            return false;
        };
        match receiver.recv_timeout(timeout.unwrap_or(HTTP_RESPONSE_WAIT)) {
            Ok(result) => {
                self.finish(result);
                self.response.is_some()
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.receiver = Some(receiver);
                false
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.finish(Err("HTTP worker stopped before returning a response".to_owned()));
                false
            }
        }
    }

    fn response_error(&self) -> u32 {
        if self.error.is_some() { ERROR_HTTP_STATE } else { ERROR_TIMEOUT }
    }
}

/// HTTP requests and worker channels are process resources, so save states
/// intentionally restore this service empty rather than serializing live work.
pub struct HttpState {
    initialized: bool,
    next_context: u32,
    contexts: BTreeMap<u32, HttpContext>,
    replacements: Vec<(String, String)>,
}

impl Default for HttpState {
    fn default() -> Self {
        Self {
            initialized: false,
            next_context: 1,
            contexts: BTreeMap::new(),
            replacements: Vec::new(),
        }
    }
}

impl HttpState {
    fn allocate(&mut self, request: HttpRequest) -> u32 {
        let handle = self.next_context.max(1);
        self.next_context = handle.wrapping_add(1).max(1);
        self.contexts.insert(handle, HttpContext {
            request,
            state: STATE_NOT_STARTED,
            response: None,
            receiver: None,
            error: None,
            body_offset: 0,
        });
        handle
    }

    fn url(&self, url: &str, provider: NetworkProvider) -> String {
        let mut rewritten = crate::services::soc::rewrite_network_url(url, provider);
        for (pattern, replacement) in &self.replacements {
            rewritten = rewritten.replace(pattern, replacement);
        }
        rewritten
    }
}

fn start_request(system: &mut System, handle: u32) -> Result<(), u32> {
    let provider = system.config.network_provider;
    let data_dir = system.config.data_dir.clone();
    let rewritten_url = system.services.http.contexts.get(&handle)
        .map(|context| system.services.http.url(&context.request.url, provider));
    let (url, request) = match (rewritten_url, system.services.http.contexts.get(&handle)) {
        (Some(url), Some(context)) if context.state == STATE_NOT_STARTED => {
            let request = RequestToRun {
                url,
                method: context.request.method,
                headers: context.request.headers.clone(),
                post_fields: context.request.post_fields.clone(),
                raw_body: context.request.raw_body.clone(),
                multipart: context.request.force_multipart
                    || context.request.post_data_encoding == 2
                    || context.request.post_data_type == 1,
                use_client_certificate: context.request.use_client_certificate
                    || (provider == NetworkProvider::Pretendo
                        && context.request.url.to_ascii_lowercase().contains("nasc.")),
                data_dir,
            };
            (request.url.clone(), request)
        }
        (Some(_), Some(_)) => return Err(ERROR_HTTP_STATE),
        _ => return Err(not_connected()),
    };
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ERROR_HTTP_STATE);
    }

    let (send, receive) = mpsc::channel();
    if let Some(context) = system.services.http.contexts.get_mut(&handle) {
        context.receiver = Some(receive);
        context.state = STATE_CONNECTING;
        context.request.post_pending_request = false;
    }
    thread::spawn(move || {
        let result = perform_request(request);
        let _ = send.send(result);
    });
    Ok(())
}

/// Handles the HTTP:C commands required by basic HTTP/HTTPS requests.
pub fn handle(system: &mut System, buffer: &CommandBuffer, header: Header) -> bool {
    let command = header.command_id();
    match command {
        // Initialize(shared memory size, current process id, shared memory handle)
        0x0001 => {
            system.services.http.initialized = true;
            buffer.reply(&mut system.memory, command, &[]);
        }
        // CreateContext(url length, request method, mapped URL)
        0x0002 => {
            let (length, method) = (buffer.get(&mut system.memory, 1) as usize, buffer.get(&mut system.memory, 2));
            let Some((descriptor, pointer, bytes)) = mapped_bytes(system, buffer, header, 0, length.min(MAX_URL)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let url = nul_string(&bytes);
            if !system.services.http.initialized || !valid_method(method) || url.is_empty() {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            }
            let request = HttpRequest {
                url,
                method,
                headers: Vec::new(),
                post_fields: Vec::new(),
                raw_body: None,
                force_multipart: false,
                post_data_encoding: 0,
                chunked_request: false,
                post_data_type: 0,
                post_data_added: false,
                post_pending_request: false,
                use_client_certificate: false,
            };
            let context = system.services.http.allocate(request);
            buffer.set(&mut system.memory, 0, Header::new(command, 2, 2).0);
            buffer.set(&mut system.memory, 1, 0);
            buffer.set(&mut system.memory, 2, context);
            buffer.set(&mut system.memory, 3, descriptor);
            buffer.set(&mut system.memory, 4, pointer);
        }
        // CloseContext(handle)
        0x0003 => {
            let handle = buffer.get(&mut system.memory, 1);
            system.services.http.contexts.remove(&handle);
            buffer.reply(&mut system.memory, command, &[]);
        }
        // CancelConnection(handle)
        0x0004 => {
            let handle = buffer.get(&mut system.memory, 1);
            if let Some(context) = system.services.http.contexts.get_mut(&handle) {
                context.receiver = None;
                context.state = STATE_COMPLETED;
                context.error = Some("request cancelled".to_owned());
            }
            buffer.reply(&mut system.memory, command, &[]);
        }
        // GetRequestState(handle)
        0x0005 => {
            let handle = buffer.get(&mut system.memory, 1);
            let state = system.services.http.contexts.get_mut(&handle).map(|context| {
                context.refresh();
                context.state
            });
            match state {
                Some(state) => buffer.reply(&mut system.memory, command, &[state]),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
        // GetDownloadSizeState(handle)
        0x0006 => {
            let handle = buffer.get(&mut system.memory, 1);
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                context.refresh();
                let size = context.response.as_ref().map_or(0, |response| response.body.len());
                (context.body_offset as u32, size as u32)
            });
            match result {
                Some((downloaded, total)) => buffer.reply(&mut system.memory, command, &[downloaded, total]),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
        // GetRequestError(handle), a non-zero result when the host request failed.
        0x0007 => {
            let handle = buffer.get(&mut system.memory, 1);
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                context.refresh();
                u32::from(context.error.is_some())
            });
            match result {
                Some(error) => buffer.reply(&mut system.memory, command, &[error]),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
        // InitializeConnectionSession(handle, current process id)
        0x0008 => {
            let handle = buffer.get(&mut system.memory, 1);
            if system.services.http.contexts.contains_key(&handle) {
                buffer.reply(&mut system.memory, command, &[]);
            } else {
                buffer.reply_error(&mut system.memory, command, not_connected());
            }
        }
        // BeginRequest / BeginRequestAsync. A POST with no fields yet stays
        // pending so the guest can stream SendPostData* calls and notify finish.
        0x0009 | 0x000A => {
            let handle = buffer.get(&mut system.memory, 1);
            let pending = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED {
                    return Err(ERROR_HTTP_STATE);
                }
                if context.request.method == HTTP_POST && !context.request.post_data_added {
                    context.request.post_pending_request = true;
                    Ok(true)
                } else {
                    Ok(false)
                }
            });
            match pending {
                Some(Ok(true)) => buffer.reply(&mut system.memory, command, &[]),
                Some(Ok(false)) => match start_request(system, handle) {
                    Ok(()) => buffer.reply(&mut system.memory, command, &[]),
                    Err(error) => buffer.reply_error(&mut system.memory, command, error),
                },
                Some(Err(error)) => buffer.reply_error(&mut system.memory, command, error),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
        // ReceiveData(handle, size, mapped writable buffer)
        0x000B | 0x000C => receive_data(system, buffer, header),
        // AddRequestHeader(handle, name length, value length, static name, mapped value)
        0x0011 => {
            let handle = buffer.get(&mut system.memory, 1);
            let name_len = buffer.get(&mut system.memory, 2) as usize;
            let value_len = buffer.get(&mut system.memory, 3) as usize;
            let name = read_static(system, buffer, header, 0, name_len.min(MAX_HEADER));
            let Some((descriptor, pointer, value)) = mapped_bytes(system, buffer, header, 0, value_len.min(MAX_HEADER)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let name = nul_string(&name);
            let value = nul_string(&value);
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || name.is_empty() { false }
                else {
                    context.request.headers.push((name, value));
                    true
                }
            }).unwrap_or(false);
            if result { reply_mapped(system, buffer, command, &[], descriptor, pointer); }
            else { reply_mapped_error(system, buffer, command, not_connected(), descriptor, pointer); }
        }
        // AddPostDataAscii(handle, name length, value length, static name, mapped value)
        0x0012 => {
            let handle = buffer.get(&mut system.memory, 1);
            let name_len = buffer.get(&mut system.memory, 2) as usize;
            let value_len = buffer.get(&mut system.memory, 3) as usize;
            let name = nul_string(&read_static(system, buffer, header, 0, name_len.min(MAX_HEADER)));
            let Some((descriptor, pointer, value)) = mapped_bytes(system, buffer, header, 0, value_len.min(MAX_HEADER)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let value = nul_string(&value).into_bytes();
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || context.request.chunked_request
                    || context.request.raw_body.is_some() || name.is_empty() {
                    Err(ERROR_HTTP_STATE)
                } else {
                    context.request.post_fields.push((name, value));
                    context.request.post_data_added = true;
                    Ok(())
                }
            });
            match result {
                Some(Ok(())) => reply_mapped(system, buffer, command, &[], descriptor, pointer),
                Some(Err(error)) => reply_mapped_error(system, buffer, command, error, descriptor, pointer),
                None => reply_mapped_error(system, buffer, command, not_connected(), descriptor, pointer),
            }
        }
        // AddPostDataBinary(handle, name length, value length, static name, mapped value)
        0x0013 => {
            let handle = buffer.get(&mut system.memory, 1);
            let name_len = buffer.get(&mut system.memory, 2) as usize;
            let value_len = buffer.get(&mut system.memory, 3) as usize;
            let name = nul_string(&read_static(system, buffer, header, 0, name_len.min(MAX_HEADER)));
            let Some((descriptor, pointer, value)) = mapped_bytes(system, buffer, header, 0, value_len.min(MAX_BODY)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || context.request.chunked_request
                    || context.request.raw_body.is_some() || name.is_empty() {
                    Err(ERROR_HTTP_STATE)
                } else {
                    context.request.post_fields.push((name, value));
                    context.request.force_multipart = true;
                    context.request.post_data_added = true;
                    Ok(())
                }
            });
            match result {
                Some(Ok(())) => reply_mapped(system, buffer, command, &[], descriptor, pointer),
                Some(Err(error)) => reply_mapped_error(system, buffer, command, error, descriptor, pointer),
                None => reply_mapped_error(system, buffer, command, not_connected(), descriptor, pointer),
            }
        }
        // AddPostDataRaw(handle, length, mapped bytes)
        0x0014 => {
            let handle = buffer.get(&mut system.memory, 1);
            let length = buffer.get(&mut system.memory, 2) as usize;
            let Some((descriptor, pointer, bytes)) = mapped_bytes(system, buffer, header, 0, length.min(MAX_BODY)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || context.request.chunked_request
                    || !context.request.post_fields.is_empty() || context.request.raw_body.is_some() {
                    Err(0xD8A0_A032)
                } else {
                    context.request.raw_body = Some(bytes);
                    context.request.post_data_added = true;
                    Ok(())
                }
            });
            match result {
                Some(Ok(())) => reply_mapped(system, buffer, command, &[], descriptor, pointer),
                Some(Err(error)) => reply_mapped_error(system, buffer, command, error, descriptor, pointer),
                None => reply_mapped_error(system, buffer, command, not_connected(), descriptor, pointer),
            }
        }
        // SetPostDataType(handle, type): 0 ASCII, 1 multipart, 2 raw.
        0x0015 => {
            let handle = buffer.get(&mut system.memory, 1);
            let data_type = buffer.get(&mut system.memory, 2);
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || context.request.post_data_added
                    || context.request.raw_body.is_some() || data_type > 2 {
                    Err(ERROR_HTTP_STATE)
                } else {
                    context.request.chunked_request = true;
                    context.request.post_data_type = data_type;
                    Ok(())
                }
            });
            match result {
                Some(Ok(())) => buffer.reply(&mut system.memory, command, &[]),
                Some(Err(error)) => buffer.reply_error(&mut system.memory, command, error),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
        // SendPostDataAscii / timeout variant.
        0x0016 | 0x0017 => {
            let handle = buffer.get(&mut system.memory, 1);
            let name_len = buffer.get(&mut system.memory, 2) as usize;
            let value_len = buffer.get(&mut system.memory, 3) as usize;
            let name = nul_string(&read_static(system, buffer, header, 0, name_len.min(MAX_HEADER)));
            let Some((descriptor, pointer, value)) = mapped_bytes(system, buffer, header, 0, value_len.min(MAX_HEADER)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || !context.request.chunked_request
                    || context.request.post_data_type != 0 || name.is_empty() {
                    Err(ERROR_HTTP_STATE)
                } else {
                    context.request.post_fields.push((name, nul_string(&value).into_bytes()));
                    context.request.post_data_added = true;
                    Ok(())
                }
            });
            match result {
                Some(Ok(())) => reply_mapped(system, buffer, command, &[], descriptor, pointer),
                Some(Err(error)) => reply_mapped_error(system, buffer, command, error, descriptor, pointer),
                None => reply_mapped_error(system, buffer, command, not_connected(), descriptor, pointer),
            }
        }
        // SendPostDataBinary / timeout variant.
        0x0018 | 0x0019 => {
            let handle = buffer.get(&mut system.memory, 1);
            let name_len = buffer.get(&mut system.memory, 2) as usize;
            let value_len = buffer.get(&mut system.memory, 3) as usize;
            let name = nul_string(&read_static(system, buffer, header, 0, name_len.min(MAX_HEADER)));
            let Some((descriptor, pointer, value)) = mapped_bytes(system, buffer, header, 0, value_len.min(MAX_BODY)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || !context.request.chunked_request
                    || context.request.post_data_type == 2 || name.is_empty() {
                    Err(ERROR_HTTP_STATE)
                } else {
                    context.request.post_fields.push((name, value));
                    context.request.force_multipart = true;
                    context.request.post_data_added = true;
                    Ok(())
                }
            });
            match result {
                Some(Ok(())) => reply_mapped(system, buffer, command, &[], descriptor, pointer),
                Some(Err(error)) => reply_mapped_error(system, buffer, command, error, descriptor, pointer),
                None => reply_mapped_error(system, buffer, command, not_connected(), descriptor, pointer),
            }
        }
        // SendPostDataRaw / timeout variant.
        0x001A | 0x001B => {
            let handle = buffer.get(&mut system.memory, 1);
            let length = buffer.get(&mut system.memory, 2) as usize;
            let Some((descriptor, pointer, bytes)) = mapped_bytes(system, buffer, header, 0, length.min(MAX_BODY)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || !context.request.chunked_request
                    || context.request.post_data_type != 2 || !context.request.post_fields.is_empty() {
                    Err(ERROR_HTTP_STATE)
                } else {
                    let raw = context.request.raw_body.get_or_insert_with(Vec::new);
                    if raw.len().saturating_add(bytes.len()) > MAX_BODY {
                        return Err(ERROR_HTTP_STATE);
                    }
                    raw.extend_from_slice(&bytes);
                    context.request.post_data_added = true;
                    Ok(())
                }
            });
            match result {
                Some(Ok(())) => reply_mapped(system, buffer, command, &[], descriptor, pointer),
                Some(Err(error)) => reply_mapped_error(system, buffer, command, error, descriptor, pointer),
                None => reply_mapped_error(system, buffer, command, not_connected(), descriptor, pointer),
            }
        }
        // SetPostDataEncoding(handle, encoding): auto, ASCII form, multipart.
        0x001C => {
            let handle = buffer.get(&mut system.memory, 1);
            let encoding = buffer.get(&mut system.memory, 2);
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.state != STATE_NOT_STARTED || context.request.raw_body.is_some() || encoding > 2 {
                    Err(ERROR_HTTP_STATE)
                } else {
                    context.request.post_data_encoding = encoding;
                    Ok(())
                }
            });
            match result {
                Some(Ok(())) => buffer.reply(&mut system.memory, command, &[]),
                Some(Err(error)) => buffer.reply_error(&mut system.memory, command, error),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
        // NotifyFinishSendPostData starts the buffered chunked POST.
        0x001D => {
            let handle = buffer.get(&mut system.memory, 1);
            let result = system.services.http.contexts.get(&handle).map(|context| {
                if context.state == STATE_NOT_STARTED && context.request.post_pending_request
                    && context.request.post_data_added {
                    Ok(())
                } else {
                    Err(ERROR_HTTP_STATE)
                }
            });
            match result {
                Some(Ok(())) => match start_request(system, handle) {
                    Ok(()) => buffer.reply(&mut system.memory, command, &[]),
                    Err(error) => buffer.reply_error(&mut system.memory, command, error),
                },
                Some(Err(error)) => buffer.reply_error(&mut system.memory, command, error),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
        // SetDefaultClientCert(handle, certificate id)
        0x0028 => {
            let (handle, certificate_id) = (buffer.get(&mut system.memory, 1), buffer.get(&mut system.memory, 2));
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if certificate_id == CLIENT_CERT_DEFAULT && context.state == STATE_NOT_STARTED {
                    context.request.use_client_certificate = true;
                    true
                } else { false }
            }).unwrap_or(false);
            if result { buffer.reply(&mut system.memory, command, &[]); }
            else { buffer.reply_error(&mut system.memory, command, ERROR_HTTP_STATE); }
        }
        // GetResponseStatusCode(handle[, timeout])
        0x0022 | 0x0023 => {
            let handle = buffer.get(&mut system.memory, 1);
            let timeout = if command == 0x0023 {
                Some(Duration::from_nanos(read_u64_words(system, buffer, 2)))
            } else {
                None
            };
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if context.wait_for_response(timeout) {
                    Ok(context.response.as_ref().unwrap().status)
                } else {
                    Err(context.response_error())
                }
            });
            match result {
                Some(Ok(status)) => buffer.reply(&mut system.memory, command, &[status]),
                Some(Err(error)) => buffer.reply_error(&mut system.memory, command, error),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
                // GetResponseHeader(handle, name length, value capacity[, timeout], static name, mapped output)
        0x001E | 0x001F => {
            let (handle, name_len, capacity) = (
                buffer.get(&mut system.memory, 1),
                buffer.get(&mut system.memory, 2) as usize,
                buffer.get(&mut system.memory, 3) as usize,
            );
            let timeout = if command == 0x001F {
                Some(Duration::from_nanos(read_u64_words(system, buffer, 4)))
            } else {
                None
            };
            let name = nul_string(&read_static(system, buffer, header, 0, name_len.min(MAX_HEADER)));
            let Some((descriptor, pointer, _)) = mapped_bytes(system, buffer, header, 0, capacity.min(MAX_HEADER)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let result = system.services.http.contexts.get_mut(&handle).map(|context| {
                if !context.wait_for_response(timeout) {
                    return Err(context.response_error());
                }
                context.response.as_ref().and_then(|response| {
                    response.headers.iter()
                        .find(|(key, _)| key.eq_ignore_ascii_case(&name))
                        .map(|(_, value)| value.clone())
                }).ok_or(ERROR_HEADER_NOT_FOUND)
            });
            match result {
                Some(Ok(value)) => {
                    let copied_size = value.len() as u32;
                    let mut bytes = value.into_bytes();
                    if capacity > 0 {
                        bytes.truncate(capacity - 1);
                        bytes.push(0);
                    } else {
                        bytes.clear();
                    }
                    system.memory.write_bytes(pointer, &bytes);
                    reply_mapped(system, buffer, command, &[copied_size], descriptor, pointer);
                }
                Some(Err(error)) => reply_mapped_error(system, buffer, command, error, descriptor, pointer),
                None => reply_mapped_error(system, buffer, command, not_connected(), descriptor, pointer),
            }
        }
                // GetResponseData(handle, capacity[, timeout], mapped output): raw response headers.
        0x0020 | 0x0021 => {
            let (handle, capacity) = (
                buffer.get(&mut system.memory, 1),
                buffer.get(&mut system.memory, 2) as usize,
            );
            let timeout = if command == 0x0021 {
                Some(Duration::from_nanos(read_u64_words(system, buffer, 3)))
            } else {
                None
            };
            let Some((_descriptor, pointer, _)) = mapped_bytes(system, buffer, header, 0, capacity.min(MAX_BODY)) else {
                buffer.reply_error(&mut system.memory, command, not_connected());
                return true;
            };
            let response = system.services.http.contexts.get_mut(&handle).map(|context| {
                if !context.wait_for_response(timeout) {
                    return Err(context.response_error());
                }
                let response = context.response.as_ref().unwrap();
                let reason = if response.reason.is_empty() {
                    reason_phrase(response.status)
                } else {
                    response.reason.as_str()
                };
                let mut text = format!("{} {} {}\r\n", response.version, response.status, reason);
                for (name, value) in &response.headers {
                    text.push_str(&format!("{name}: {value}\r\n"));
                }
                text.push_str("\r\n");
                Ok(text.into_bytes())
            });
            match response {
                Some(Ok(bytes)) => {
                    let count = bytes.len().min(capacity);
                    system.memory.write_bytes(pointer, &bytes[..count]);
                    buffer.reply(&mut system.memory, command, &[count as u32]);
                }
                Some(Err(error)) => buffer.reply_error(&mut system.memory, command, error),
                None => buffer.reply_error(&mut system.memory, command, not_connected()),
            }
        }
                // RegisterURLReplacement(pattern length, replacement length, two static buffers)
        0x0C00 => {
            let (pattern_len, replacement_len) = (buffer.get(&mut system.memory, 1) as usize, buffer.get(&mut system.memory, 2) as usize);
            let pattern = nul_string(&read_static(system, buffer, header, 0, pattern_len.min(MAX_URL)));
            let replacement = nul_string(&read_static(system, buffer, header, 1, replacement_len.min(MAX_URL)));
            if pattern.is_empty() { buffer.reply_error(&mut system.memory, command, not_connected()); }
            else {
                system.services.http.replacements.push((pattern, replacement));
                buffer.reply(&mut system.memory, command, &[]);
            }
        }
        // UnregisterURLReplacement(pattern length, static pattern)
        0x0C01 => {
            let length = buffer.get(&mut system.memory, 1) as usize;
            let pattern = nul_string(&read_static(system, buffer, header, 0, length.min(MAX_URL)));
            let before = system.services.http.replacements.len();
            system.services.http.replacements.retain(|(known, _)| known != &pattern);
            if before == system.services.http.replacements.len() { buffer.reply_error(&mut system.memory, command, not_connected()); }
            else { buffer.reply(&mut system.memory, command, &[]); }
        }
        // Finalize
        0x0039 => {
            system.services.http.initialized = false;
            system.services.http.contexts.clear();
            system.services.http.replacements.clear();
            buffer.reply(&mut system.memory, command, &[]);
        }
        _ => return false,
    }
    true
}

struct RequestToRun {
    url: String,
    method: u32,
    headers: Vec<(String, String)>,
    post_fields: Vec<(String, Vec<u8>)>,
    raw_body: Option<Vec<u8>>,
    multipart: bool,
    use_client_certificate: bool,
    data_dir: Option<PathBuf>,
}

fn perform_request(request: RequestToRun) -> Result<HttpResponse, String> {
    if request.url.len() > MAX_URL { return Err("URL exceeds the HTTP service limit".to_owned()); }
    if !(request.url.starts_with("http://") || request.url.starts_with("https://")) {
        return Err("only HTTP and HTTPS URLs are supported by the guest HTTP service".to_owned());
    }
    let method = match request.method {
        HTTP_GET => "GET",
        HTTP_POST | HTTP_POST_EMPTY => "POST",
        HTTP_HEAD => "HEAD",
        HTTP_PUT | HTTP_PUT_EMPTY => "PUT",
        HTTP_DELETE => "DELETE",
        _ => return Err("unsupported HTTP method".to_owned()),
    };

    let id = NEXT_REQUEST_ID.fetch_add(1, Ordering::Relaxed);
    let mut content_type = None;
    let body = if let Some(raw) = request.raw_body {
        raw
    } else if request.post_fields.is_empty() {
        Vec::new()
    } else if request.multipart {
        let boundary = format!("----MK7Recomp-{}-{id}", std::process::id());
        content_type = Some(format!("multipart/form-data; boundary={boundary}"));
        multipart_encode(&request.post_fields, &boundary)
    } else {
        content_type = Some("application/x-www-form-urlencoded".to_owned());
        form_encode(&request.post_fields).into_bytes()
    };
    if body.len() > MAX_BODY { return Err("HTTP request body exceeds 16 MiB".to_owned()); }

    let cert = request.data_dir.as_ref().map(|dir| dir.join("sysdata/ctr-common-1-cert.pem"));
    let key = request.data_dir.as_ref().map(|dir| dir.join("sysdata/ctr-common-1-key.pem"));
    if request.use_client_certificate && (!cert.as_ref().is_some_and(|path| path.is_file()) || !key.as_ref().is_some_and(|path| path.is_file())) {
        return Err("Pretendo NASC requires your own decrypted ctr-common-1 certificate and private key at sysdata/ctr-common-1-cert.pem and sysdata/ctr-common-1-key.pem".to_owned());
    }

    let directory = std::env::temp_dir().join(format!("mk7recomp-http-{}-{id}", std::process::id()));
    std::fs::create_dir_all(&directory).map_err(|error| format!("could not create HTTP temp directory: {error}"))?;
    let body_path = directory.join("response.bin");
    let header_path = directory.join("headers.txt");

    let result = (|| {
        let mut command = Command::new("curl");
        command.args([
            "--silent", "--show-error",
            "--proto", "=http,https",
            "--connect-timeout", "12", "--max-time", "35",
            "--dump-header", header_path.to_str().ok_or_else(|| "invalid HTTP header output path".to_owned())?,
            "--output", body_path.to_str().ok_or_else(|| "invalid HTTP body output path".to_owned())?,
            "--write-out", "%{http_code}",
            "--request", method,
        ]);
        for (name, value) in &request.headers {
            command.arg("--header").arg(format!("{name}: {value}"));
        }
        if let Some(content_type) = &content_type {
            if !request.headers.iter().any(|(name, _)| name.eq_ignore_ascii_case("content-type")) {
                command.arg("--header").arg(format!("Content-Type: {content_type}"));
            }
        }
        if request.use_client_certificate {
            command.arg("--cert").arg(cert.as_ref().unwrap());
            command.arg("--key").arg(key.as_ref().unwrap());
        }
        if method == "POST" || method == "PUT" {
            command.arg("--data-binary").arg("@-").stdin(Stdio::piped());
        } else {
            command.stdin(Stdio::null());
        }
        if !request.use_client_certificate {
            command.args(["--location", "--proto-redir", "=https"]);
        }
        command.arg(&request.url).stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = command.spawn().map_err(|error| format!("could not start curl: {error}"))?;
        if method == "POST" || method == "PUT" {
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(&body).map_err(|error| format!("could not send HTTP request body: {error}"))?;
            }
        }
        let output = child.wait_with_output().map_err(|error| format!("curl failed: {error}"))?;
        if !output.status.success() {
            let message = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            return Err(if message.is_empty() { format!("curl exited with {}", output.status) } else { message });
        }
        let status_text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let status = status_text.parse::<u32>().map_err(|_| format!("curl returned an invalid HTTP status: {status_text}"))?;
        let body_size = std::fs::metadata(&body_path).map_err(|error| format!("could not inspect HTTP response body: {error}"))?.len();
        if body_size > MAX_BODY as u64 { return Err("HTTP response body exceeds 16 MiB".to_owned()); }
        let header_size = std::fs::metadata(&header_path).map(|metadata| metadata.len()).unwrap_or(0);
        if header_size > 1024 * 1024 { return Err("HTTP response headers exceed 1 MiB".to_owned()); }
        let response_body = std::fs::read(&body_path).map_err(|error| format!("could not read HTTP response body: {error}"))?;
        let response_headers = std::fs::read_to_string(&header_path).unwrap_or_default();
        let (version, reason, headers) = parse_response_headers(&response_headers);
        Ok(HttpResponse { status, version, reason, headers, body: response_body })
    })();

    let _ = std::fs::remove_dir_all(&directory);
    result
}

fn parse_response_headers(raw: &str) -> (String, String, BTreeMap<String, String>) {
    let mut version = "HTTP/1.1".to_owned();
    let mut reason = String::new();
    let mut headers = BTreeMap::new();
    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("HTTP/") {
            headers.clear();
            let mut parts = line.splitn(3, ' ');
            version = parts.next().unwrap_or("HTTP/1.1").to_owned();
            let _status = parts.next();
            reason = parts.next().unwrap_or_default().to_owned();
        } else if let Some((name, value)) = line.split_once(':') {
            headers.insert(name.trim().to_owned(), value.trim().to_owned());
        }
    }
    (version, reason, headers)
}

fn parse_headers(raw: &str) -> BTreeMap<String, String> {
    parse_response_headers(raw).2
}

fn reason_phrase(status: u32) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Response",
    }
}


fn form_encode(fields: &[(String, Vec<u8>)]) -> String {
    fields.iter()
        .map(|(name, value)| format!("{}={}", url_encode(name.as_bytes()), url_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn url_encode(value: &[u8]) -> String {
    let mut out = String::new();
    for byte in value {
        if *byte == b' ' {
            out.push('+');
        } else if byte.is_ascii_alphanumeric() || matches!(*byte, b'*' | b'-' | b'.' | b'_') {
            out.push(*byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn multipart_encode(fields: &[(String, Vec<u8>)], boundary: &str) -> Vec<u8> {
    let mut body = Vec::new();
    for (name, value) in fields {
        let safe_name = name.replace('\\', "\\\\").replace('"', "\\\"");
        body.extend_from_slice(format!("--{boundary}\r\n").as_bytes());
        body.extend_from_slice(
            format!("Content-Disposition: form-data; name=\"{safe_name}\"\r\n\r\n").as_bytes()
        );
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    body
}


fn read_u64_words(system: &mut System, buffer: &CommandBuffer, index: u32) -> u64 {
    buffer.get(&mut system.memory, index) as u64
        | ((buffer.get(&mut system.memory, index + 1) as u64) << 32)
}

fn valid_method(method: u32) -> bool {
    (HTTP_GET..=HTTP_PUT_EMPTY).contains(&method)
}

fn nul_string(bytes: &[u8]) -> String {
    let length = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

fn not_connected() -> u32 {
    zakuro_common::result::errors::NOT_CONNECTED.0
}

fn translated_buffer(
    system: &mut System,
    buffer: &CommandBuffer,
    header: Header,
    mapped: bool,
    ordinal: u32,
) -> Option<(u32, u32, usize)> {
    let mut index = header.normal_params() + 1;
    let end = index + header.translate_params();
    let mut found = 0u32;
    while index < end {
        let raw = buffer.get(&mut system.memory, index);
        match Descriptor::parse(raw) {
            Descriptor::Handles { count, .. } => index += count + 1,
            Descriptor::CurrentProcessId => index += 2,
            Descriptor::StaticBuffer { size, buffer_id } => {
                if !mapped && found == ordinal {
                    let pointer = buffer.get(&mut system.memory, index + 1);
                    return Some((raw, pointer, size as usize));
                }
                if !mapped { found += 1; }
                index += 2;
            }
            Descriptor::MappedBuffer { size, .. } => {
                let pointer = buffer.get(&mut system.memory, index + 1);
                if mapped && found == ordinal {
                    return Some((raw, pointer, size as usize));
                }
                if mapped { found += 1; }
                index += 2;
            }
            Descriptor::Unknown(_) => index += 1,
        }
    }
    None
}

fn read_static(
    system: &mut System,
    buffer: &CommandBuffer,
    header: Header,
    ordinal: u32,
    requested: usize,
) -> Vec<u8> {
    let Some((_, pointer, capacity)) = translated_buffer(system, buffer, header, false, ordinal) else {
        return Vec::new();
    };
    let length = requested.min(capacity);
    let mut bytes = vec![0; length];
    system.memory.read_bytes(pointer, &mut bytes);
    bytes
}

/// Returns the original descriptor, pointer and a bounded copy of a guest mapped buffer.
fn mapped_bytes(
    system: &mut System,
    buffer: &CommandBuffer,
    header: Header,
    ordinal: u32,
    requested: usize,
) -> Option<(u32, u32, Vec<u8>)> {
    let (descriptor, pointer, capacity) = translated_buffer(system, buffer, header, true, ordinal)?;
    let length = requested.min(capacity);
    let mut bytes = vec![0; length];
    system.memory.read_bytes(pointer, &mut bytes);
    Some((descriptor, pointer, bytes))
}

fn reply_mapped(system: &mut System, buffer: &CommandBuffer, command: u16, values: &[u32], descriptor: u32, pointer: u32) {
    let normal = values.len() as u32 + 1;
    buffer.set(&mut system.memory, 0, Header::new(command, normal, 2).0);
    buffer.set(&mut system.memory, 1, 0);
    for (index, value) in values.iter().enumerate() {
        buffer.set(&mut system.memory, index as u32 + 2, *value);
    }
    buffer.set(&mut system.memory, normal + 1, descriptor);
    buffer.set(&mut system.memory, normal + 2, pointer);
}

fn reply_result(system: &mut System, buffer: &CommandBuffer, command: u16, result: u32) {
    buffer.set(&mut system.memory, 0, Header::new(command, 1, 0).0);
    buffer.set(&mut system.memory, 1, result);
}

fn reply_mapped_error(system: &mut System, buffer: &CommandBuffer, command: u16, error: u32, descriptor: u32, pointer: u32) {
    buffer.set(&mut system.memory, 0, Header::new(command, 1, 2).0);
    buffer.set(&mut system.memory, 1, error);
    buffer.set(&mut system.memory, 2, descriptor);
    buffer.set(&mut system.memory, 3, pointer);
}

fn receive_data(system: &mut System, buffer: &CommandBuffer, header: Header) {
    let command = header.command_id();
    let (handle, requested) = (
        buffer.get(&mut system.memory, 1),
        buffer.get(&mut system.memory, 2) as usize,
    );
    let timeout = if command == 0x000C {
        Some(Duration::from_nanos(read_u64_words(system, buffer, 3)))
    } else {
        None
    };
    let Some((_descriptor, pointer, _)) = mapped_bytes(system, buffer, header, 0, requested.min(MAX_BODY)) else {
        buffer.reply_error(&mut system.memory, command, not_connected());
        return;
    };

    let result = system.services.http.contexts.get_mut(&handle).map(|context| {
        if !context.wait_for_response(timeout) {
            return Err(context.response_error());
        }
        let response = context.response.as_ref().unwrap();
        let total = response.body.len();
        let end = context.body_offset.saturating_add(requested.min(MAX_BODY)).min(total);
        let chunk = response.body[context.body_offset.min(total)..end].to_vec();
        context.body_offset = end;
        let complete = context.body_offset >= total;
        if complete {
            context.state = STATE_COMPLETED;
        }
        Ok((chunk, complete))
    });
    match result {
        Some(Ok((chunk, complete))) => {
            system.memory.write_bytes(pointer, &chunk);
            reply_result(system, buffer, command, if complete { 0 } else { 0xD840_A02B });
        }
        Some(Err(error)) => reply_result(system, buffer, command, error),
        None => reply_result(system, buffer, command, not_connected()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translated_buffer_walk_skips_pid_and_static_descriptors() {
        use zakuro_common::memory_map::TLS_IPC_STATIC_BUFFERS;

        let (mut system, buffer) = crate::services::tests::system_with_thread();
        let tls = system.kernel.current().unwrap().tls;
        let static_descriptor = Descriptor::static_buffer(0x20, 0);
        let static_pointer: u32 = 0x0800_1000;
        let mapped_descriptor = (0x30 << 4) | 0xC;
        let mapped_pointer = 0x0800_2000;

        system.memory.write_bytes(
            tls + TLS_IPC_STATIC_BUFFERS,
            &static_descriptor.to_le_bytes(),
        );
        system.memory.write_bytes(
            tls + TLS_IPC_STATIC_BUFFERS + 4,
            &static_pointer.to_le_bytes(),
        );

        let header = Header::new(0x0002, 2, 6);
        buffer.set(&mut system.memory, 3, 0x20); // CurrentProcessId descriptor
        buffer.set(&mut system.memory, 4, 0x0000_1234); // PID
        buffer.set(&mut system.memory, 5, static_descriptor);
        buffer.set(&mut system.memory, 6, static_pointer);
        buffer.set(&mut system.memory, 7, mapped_descriptor);
        buffer.set(&mut system.memory, 8, mapped_pointer);

        let static_buffer = translated_buffer(&mut system, &buffer, header, false, 0).unwrap();
        assert_eq!(static_buffer, (static_descriptor, static_pointer, 0x20));

        let mapped_buffer = translated_buffer(&mut system, &buffer, header, true, 0).unwrap();
        assert_eq!(mapped_buffer, (mapped_descriptor, mapped_pointer, 0x30));
    }

    #[test]
    fn nas_form_fields_are_percent_encoded() {
        let fields = vec![
            ("action".to_owned(), b"LOGIN".to_vec()),
            ("ingamesn".to_owned(), b"A B&c".to_vec()),
        ];
        assert_eq!(form_encode(&fields), "action=LOGIN&ingamesn=A+B%26c");
    }

    #[test]
    fn response_headers_are_taken_from_the_final_redirect_response() {
        let (version, reason, headers) = parse_response_headers("HTTP/1.1 302 Found\r\nLocation: https://example.test\r\n\r\nHTTP/2 200\r\nContent-Length: 3\r\nX-Test: yes\r\n\r\n");
        assert_eq!(version, "HTTP/2");
        assert_eq!(reason, "");
        assert_eq!(headers.get("Content-Length").map(String::as_str), Some("3"));
        assert_eq!(headers.get("X-Test").map(String::as_str), Some("yes"));
        assert!(!headers.contains_key("Location"));
        assert_eq!(reason_phrase(200), "OK");
    }

    #[test]
    fn unsupported_methods_are_not_accepted() {
        assert!(!valid_method(0));
        assert!(valid_method(HTTP_GET));
        assert!(valid_method(HTTP_POST));
        assert!(valid_method(HTTP_PUT_EMPTY));
        assert!(!valid_method(8));
    }
}
