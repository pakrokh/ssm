use crate::{http_codec, http_speedtest_handler, net_utils, settings, tls_demultiplexer};
use std::sync::Arc;

pub(crate) struct HttpDemux {
    core_settings: Arc<settings::Settings>,
}

impl HttpDemux {
    pub fn new(core_settings: Arc<settings::Settings>) -> Self {
        Self { core_settings }
    }

    pub fn select(
        &self,
        protocol: tls_demultiplexer::Protocol,
        request: &http_codec::RequestHeaders,
    ) -> net_utils::Channel {
        if self.check_ping(request) {
            net_utils::Channel::Ping
        } else if self.check_speedtest(request) {
            net_utils::Channel::Speedtest
        } else if self.check_reverse_proxy(protocol, request) {
            net_utils::Channel::ReverseProxy
        } else {
            net_utils::Channel::Tunnel
        }
    }

    fn check_ping(&self, request: &http_codec::RequestHeaders) -> bool {
        static MARKER_HEADERS: [(http::HeaderName, http::HeaderValue); 2] = [
            (
                http::HeaderName::from_static("x-ping"),
                http::HeaderValue::from_static("1"),
            ),
            (
                http::HeaderName::from_static("sec-fetch-mode"),
                http::HeaderValue::from_static("navigate"),
            ),
        ];

        MARKER_HEADERS
            .iter()
            .any(|(name, value)| request.headers.get(name) == Some(value))
    }

    fn check_speedtest(&self, request: &http_codec::RequestHeaders) -> bool {
        if !self.core_settings.speedtest_enable {
            return false;
        }
        request
            .uri
            .path()
            .strip_prefix('/')
            .and_then(|x| x.strip_prefix(http_speedtest_handler::SKIPPABLE_PATH_SEGMENT))
            .and_then(|x| x.strip_prefix('/'))
            .is_some()
    }

    fn check_reverse_proxy(
        &self,
        protocol: tls_demultiplexer::Protocol,
        request: &http_codec::RequestHeaders,
    ) -> bool {
        match protocol {
            tls_demultiplexer::Protocol::Http1 => {
                if !request.headers.contains_key(http::header::UPGRADE) {
                    return false;
                }
            }
            tls_demultiplexer::Protocol::Http3 => (),
            _ => return false,
        }

        self.core_settings
            .reverse_proxy
            .as_ref()
            .map(|x| x.path_mask.as_str())
            .is_some_and(|x| request.uri.path().starts_with(x))
    }
}
