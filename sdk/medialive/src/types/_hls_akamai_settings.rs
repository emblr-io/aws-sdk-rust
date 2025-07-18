// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Hls Akamai Settings
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HlsAkamaiSettings {
    /// Number of seconds to wait before retrying connection to the CDN if the connection is lost.
    pub connection_retry_interval: ::std::option::Option<i32>,
    /// Size in seconds of file cache for streaming outputs.
    pub filecache_duration: ::std::option::Option<i32>,
    /// Specify whether or not to use chunked transfer encoding to Akamai. User should contact Akamai to enable this feature.
    pub http_transfer_mode: ::std::option::Option<crate::types::HlsAkamaiHttpTransferMode>,
    /// Number of retry attempts that will be made before the Live Event is put into an error state. Applies only if the CDN destination URI begins with "s3" or "mediastore". For other URIs, the value is always 3.
    pub num_retries: ::std::option::Option<i32>,
    /// If a streaming output fails, number of seconds to wait until a restart is initiated. A value of 0 means never restart.
    pub restart_delay: ::std::option::Option<i32>,
    /// Salt for authenticated Akamai.
    pub salt: ::std::option::Option<::std::string::String>,
    /// Token parameter for authenticated akamai. If not specified, _gda_ is used.
    pub token: ::std::option::Option<::std::string::String>,
}
impl HlsAkamaiSettings {
    /// Number of seconds to wait before retrying connection to the CDN if the connection is lost.
    pub fn connection_retry_interval(&self) -> ::std::option::Option<i32> {
        self.connection_retry_interval
    }
    /// Size in seconds of file cache for streaming outputs.
    pub fn filecache_duration(&self) -> ::std::option::Option<i32> {
        self.filecache_duration
    }
    /// Specify whether or not to use chunked transfer encoding to Akamai. User should contact Akamai to enable this feature.
    pub fn http_transfer_mode(&self) -> ::std::option::Option<&crate::types::HlsAkamaiHttpTransferMode> {
        self.http_transfer_mode.as_ref()
    }
    /// Number of retry attempts that will be made before the Live Event is put into an error state. Applies only if the CDN destination URI begins with "s3" or "mediastore". For other URIs, the value is always 3.
    pub fn num_retries(&self) -> ::std::option::Option<i32> {
        self.num_retries
    }
    /// If a streaming output fails, number of seconds to wait until a restart is initiated. A value of 0 means never restart.
    pub fn restart_delay(&self) -> ::std::option::Option<i32> {
        self.restart_delay
    }
    /// Salt for authenticated Akamai.
    pub fn salt(&self) -> ::std::option::Option<&str> {
        self.salt.as_deref()
    }
    /// Token parameter for authenticated akamai. If not specified, _gda_ is used.
    pub fn token(&self) -> ::std::option::Option<&str> {
        self.token.as_deref()
    }
}
impl HlsAkamaiSettings {
    /// Creates a new builder-style object to manufacture [`HlsAkamaiSettings`](crate::types::HlsAkamaiSettings).
    pub fn builder() -> crate::types::builders::HlsAkamaiSettingsBuilder {
        crate::types::builders::HlsAkamaiSettingsBuilder::default()
    }
}

/// A builder for [`HlsAkamaiSettings`](crate::types::HlsAkamaiSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HlsAkamaiSettingsBuilder {
    pub(crate) connection_retry_interval: ::std::option::Option<i32>,
    pub(crate) filecache_duration: ::std::option::Option<i32>,
    pub(crate) http_transfer_mode: ::std::option::Option<crate::types::HlsAkamaiHttpTransferMode>,
    pub(crate) num_retries: ::std::option::Option<i32>,
    pub(crate) restart_delay: ::std::option::Option<i32>,
    pub(crate) salt: ::std::option::Option<::std::string::String>,
    pub(crate) token: ::std::option::Option<::std::string::String>,
}
impl HlsAkamaiSettingsBuilder {
    /// Number of seconds to wait before retrying connection to the CDN if the connection is lost.
    pub fn connection_retry_interval(mut self, input: i32) -> Self {
        self.connection_retry_interval = ::std::option::Option::Some(input);
        self
    }
    /// Number of seconds to wait before retrying connection to the CDN if the connection is lost.
    pub fn set_connection_retry_interval(mut self, input: ::std::option::Option<i32>) -> Self {
        self.connection_retry_interval = input;
        self
    }
    /// Number of seconds to wait before retrying connection to the CDN if the connection is lost.
    pub fn get_connection_retry_interval(&self) -> &::std::option::Option<i32> {
        &self.connection_retry_interval
    }
    /// Size in seconds of file cache for streaming outputs.
    pub fn filecache_duration(mut self, input: i32) -> Self {
        self.filecache_duration = ::std::option::Option::Some(input);
        self
    }
    /// Size in seconds of file cache for streaming outputs.
    pub fn set_filecache_duration(mut self, input: ::std::option::Option<i32>) -> Self {
        self.filecache_duration = input;
        self
    }
    /// Size in seconds of file cache for streaming outputs.
    pub fn get_filecache_duration(&self) -> &::std::option::Option<i32> {
        &self.filecache_duration
    }
    /// Specify whether or not to use chunked transfer encoding to Akamai. User should contact Akamai to enable this feature.
    pub fn http_transfer_mode(mut self, input: crate::types::HlsAkamaiHttpTransferMode) -> Self {
        self.http_transfer_mode = ::std::option::Option::Some(input);
        self
    }
    /// Specify whether or not to use chunked transfer encoding to Akamai. User should contact Akamai to enable this feature.
    pub fn set_http_transfer_mode(mut self, input: ::std::option::Option<crate::types::HlsAkamaiHttpTransferMode>) -> Self {
        self.http_transfer_mode = input;
        self
    }
    /// Specify whether or not to use chunked transfer encoding to Akamai. User should contact Akamai to enable this feature.
    pub fn get_http_transfer_mode(&self) -> &::std::option::Option<crate::types::HlsAkamaiHttpTransferMode> {
        &self.http_transfer_mode
    }
    /// Number of retry attempts that will be made before the Live Event is put into an error state. Applies only if the CDN destination URI begins with "s3" or "mediastore". For other URIs, the value is always 3.
    pub fn num_retries(mut self, input: i32) -> Self {
        self.num_retries = ::std::option::Option::Some(input);
        self
    }
    /// Number of retry attempts that will be made before the Live Event is put into an error state. Applies only if the CDN destination URI begins with "s3" or "mediastore". For other URIs, the value is always 3.
    pub fn set_num_retries(mut self, input: ::std::option::Option<i32>) -> Self {
        self.num_retries = input;
        self
    }
    /// Number of retry attempts that will be made before the Live Event is put into an error state. Applies only if the CDN destination URI begins with "s3" or "mediastore". For other URIs, the value is always 3.
    pub fn get_num_retries(&self) -> &::std::option::Option<i32> {
        &self.num_retries
    }
    /// If a streaming output fails, number of seconds to wait until a restart is initiated. A value of 0 means never restart.
    pub fn restart_delay(mut self, input: i32) -> Self {
        self.restart_delay = ::std::option::Option::Some(input);
        self
    }
    /// If a streaming output fails, number of seconds to wait until a restart is initiated. A value of 0 means never restart.
    pub fn set_restart_delay(mut self, input: ::std::option::Option<i32>) -> Self {
        self.restart_delay = input;
        self
    }
    /// If a streaming output fails, number of seconds to wait until a restart is initiated. A value of 0 means never restart.
    pub fn get_restart_delay(&self) -> &::std::option::Option<i32> {
        &self.restart_delay
    }
    /// Salt for authenticated Akamai.
    pub fn salt(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.salt = ::std::option::Option::Some(input.into());
        self
    }
    /// Salt for authenticated Akamai.
    pub fn set_salt(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.salt = input;
        self
    }
    /// Salt for authenticated Akamai.
    pub fn get_salt(&self) -> &::std::option::Option<::std::string::String> {
        &self.salt
    }
    /// Token parameter for authenticated akamai. If not specified, _gda_ is used.
    pub fn token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token = ::std::option::Option::Some(input.into());
        self
    }
    /// Token parameter for authenticated akamai. If not specified, _gda_ is used.
    pub fn set_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token = input;
        self
    }
    /// Token parameter for authenticated akamai. If not specified, _gda_ is used.
    pub fn get_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.token
    }
    /// Consumes the builder and constructs a [`HlsAkamaiSettings`](crate::types::HlsAkamaiSettings).
    pub fn build(self) -> crate::types::HlsAkamaiSettings {
        crate::types::HlsAkamaiSettings {
            connection_retry_interval: self.connection_retry_interval,
            filecache_duration: self.filecache_duration,
            http_transfer_mode: self.http_transfer_mode,
            num_retries: self.num_retries,
            restart_delay: self.restart_delay,
            salt: self.salt,
            token: self.token,
        }
    }
}
