// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Network source to transcode. Must be accessible to the Elemental Live node that is running the live event through a network connection.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NetworkInputSettings {
    /// Specifies HLS input settings when the uri is for a HLS manifest.
    pub hls_input_settings: ::std::option::Option<crate::types::HlsInputSettings>,
    /// Check HTTPS server certificates. When set to checkCryptographyOnly, cryptography in the certificate will be checked, but not the server's name. Certain subdomains (notably S3 buckets that use dots in the bucket name) do not strictly match the corresponding certificate's wildcard pattern and would otherwise cause the event to error. This setting is ignored for protocols that do not use https.
    pub server_validation: ::std::option::Option<crate::types::NetworkInputServerValidation>,
    /// Specifies multicast input settings when the uri is for a multicast event.
    pub multicast_input_settings: ::std::option::Option<crate::types::MulticastInputSettings>,
}
impl NetworkInputSettings {
    /// Specifies HLS input settings when the uri is for a HLS manifest.
    pub fn hls_input_settings(&self) -> ::std::option::Option<&crate::types::HlsInputSettings> {
        self.hls_input_settings.as_ref()
    }
    /// Check HTTPS server certificates. When set to checkCryptographyOnly, cryptography in the certificate will be checked, but not the server's name. Certain subdomains (notably S3 buckets that use dots in the bucket name) do not strictly match the corresponding certificate's wildcard pattern and would otherwise cause the event to error. This setting is ignored for protocols that do not use https.
    pub fn server_validation(&self) -> ::std::option::Option<&crate::types::NetworkInputServerValidation> {
        self.server_validation.as_ref()
    }
    /// Specifies multicast input settings when the uri is for a multicast event.
    pub fn multicast_input_settings(&self) -> ::std::option::Option<&crate::types::MulticastInputSettings> {
        self.multicast_input_settings.as_ref()
    }
}
impl NetworkInputSettings {
    /// Creates a new builder-style object to manufacture [`NetworkInputSettings`](crate::types::NetworkInputSettings).
    pub fn builder() -> crate::types::builders::NetworkInputSettingsBuilder {
        crate::types::builders::NetworkInputSettingsBuilder::default()
    }
}

/// A builder for [`NetworkInputSettings`](crate::types::NetworkInputSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NetworkInputSettingsBuilder {
    pub(crate) hls_input_settings: ::std::option::Option<crate::types::HlsInputSettings>,
    pub(crate) server_validation: ::std::option::Option<crate::types::NetworkInputServerValidation>,
    pub(crate) multicast_input_settings: ::std::option::Option<crate::types::MulticastInputSettings>,
}
impl NetworkInputSettingsBuilder {
    /// Specifies HLS input settings when the uri is for a HLS manifest.
    pub fn hls_input_settings(mut self, input: crate::types::HlsInputSettings) -> Self {
        self.hls_input_settings = ::std::option::Option::Some(input);
        self
    }
    /// Specifies HLS input settings when the uri is for a HLS manifest.
    pub fn set_hls_input_settings(mut self, input: ::std::option::Option<crate::types::HlsInputSettings>) -> Self {
        self.hls_input_settings = input;
        self
    }
    /// Specifies HLS input settings when the uri is for a HLS manifest.
    pub fn get_hls_input_settings(&self) -> &::std::option::Option<crate::types::HlsInputSettings> {
        &self.hls_input_settings
    }
    /// Check HTTPS server certificates. When set to checkCryptographyOnly, cryptography in the certificate will be checked, but not the server's name. Certain subdomains (notably S3 buckets that use dots in the bucket name) do not strictly match the corresponding certificate's wildcard pattern and would otherwise cause the event to error. This setting is ignored for protocols that do not use https.
    pub fn server_validation(mut self, input: crate::types::NetworkInputServerValidation) -> Self {
        self.server_validation = ::std::option::Option::Some(input);
        self
    }
    /// Check HTTPS server certificates. When set to checkCryptographyOnly, cryptography in the certificate will be checked, but not the server's name. Certain subdomains (notably S3 buckets that use dots in the bucket name) do not strictly match the corresponding certificate's wildcard pattern and would otherwise cause the event to error. This setting is ignored for protocols that do not use https.
    pub fn set_server_validation(mut self, input: ::std::option::Option<crate::types::NetworkInputServerValidation>) -> Self {
        self.server_validation = input;
        self
    }
    /// Check HTTPS server certificates. When set to checkCryptographyOnly, cryptography in the certificate will be checked, but not the server's name. Certain subdomains (notably S3 buckets that use dots in the bucket name) do not strictly match the corresponding certificate's wildcard pattern and would otherwise cause the event to error. This setting is ignored for protocols that do not use https.
    pub fn get_server_validation(&self) -> &::std::option::Option<crate::types::NetworkInputServerValidation> {
        &self.server_validation
    }
    /// Specifies multicast input settings when the uri is for a multicast event.
    pub fn multicast_input_settings(mut self, input: crate::types::MulticastInputSettings) -> Self {
        self.multicast_input_settings = ::std::option::Option::Some(input);
        self
    }
    /// Specifies multicast input settings when the uri is for a multicast event.
    pub fn set_multicast_input_settings(mut self, input: ::std::option::Option<crate::types::MulticastInputSettings>) -> Self {
        self.multicast_input_settings = input;
        self
    }
    /// Specifies multicast input settings when the uri is for a multicast event.
    pub fn get_multicast_input_settings(&self) -> &::std::option::Option<crate::types::MulticastInputSettings> {
        &self.multicast_input_settings
    }
    /// Consumes the builder and constructs a [`NetworkInputSettings`](crate::types::NetworkInputSettings).
    pub fn build(self) -> crate::types::NetworkInputSettings {
        crate::types::NetworkInputSettings {
            hls_input_settings: self.hls_input_settings,
            server_validation: self.server_validation,
            multicast_input_settings: self.multicast_input_settings,
        }
    }
}
