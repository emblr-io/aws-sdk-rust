// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Use these settings to set up encryption with a static key provider.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StaticKeyProvider {
    /// Relates to DRM implementation. Sets the value of the KEYFORMAT attribute. Must be 'identity' or a reverse DNS string. May be omitted to indicate an implicit value of 'identity'.
    pub key_format: ::std::option::Option<::std::string::String>,
    /// Relates to DRM implementation. Either a single positive integer version value or a slash delimited list of version values (1/2/3).
    pub key_format_versions: ::std::option::Option<::std::string::String>,
    /// Relates to DRM implementation. Use a 32-character hexidecimal string to specify Key Value.
    pub static_key_value: ::std::option::Option<::std::string::String>,
    /// Relates to DRM implementation. The location of the license server used for protecting content.
    pub url: ::std::option::Option<::std::string::String>,
}
impl StaticKeyProvider {
    /// Relates to DRM implementation. Sets the value of the KEYFORMAT attribute. Must be 'identity' or a reverse DNS string. May be omitted to indicate an implicit value of 'identity'.
    pub fn key_format(&self) -> ::std::option::Option<&str> {
        self.key_format.as_deref()
    }
    /// Relates to DRM implementation. Either a single positive integer version value or a slash delimited list of version values (1/2/3).
    pub fn key_format_versions(&self) -> ::std::option::Option<&str> {
        self.key_format_versions.as_deref()
    }
    /// Relates to DRM implementation. Use a 32-character hexidecimal string to specify Key Value.
    pub fn static_key_value(&self) -> ::std::option::Option<&str> {
        self.static_key_value.as_deref()
    }
    /// Relates to DRM implementation. The location of the license server used for protecting content.
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl StaticKeyProvider {
    /// Creates a new builder-style object to manufacture [`StaticKeyProvider`](crate::types::StaticKeyProvider).
    pub fn builder() -> crate::types::builders::StaticKeyProviderBuilder {
        crate::types::builders::StaticKeyProviderBuilder::default()
    }
}

/// A builder for [`StaticKeyProvider`](crate::types::StaticKeyProvider).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StaticKeyProviderBuilder {
    pub(crate) key_format: ::std::option::Option<::std::string::String>,
    pub(crate) key_format_versions: ::std::option::Option<::std::string::String>,
    pub(crate) static_key_value: ::std::option::Option<::std::string::String>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
}
impl StaticKeyProviderBuilder {
    /// Relates to DRM implementation. Sets the value of the KEYFORMAT attribute. Must be 'identity' or a reverse DNS string. May be omitted to indicate an implicit value of 'identity'.
    pub fn key_format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_format = ::std::option::Option::Some(input.into());
        self
    }
    /// Relates to DRM implementation. Sets the value of the KEYFORMAT attribute. Must be 'identity' or a reverse DNS string. May be omitted to indicate an implicit value of 'identity'.
    pub fn set_key_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_format = input;
        self
    }
    /// Relates to DRM implementation. Sets the value of the KEYFORMAT attribute. Must be 'identity' or a reverse DNS string. May be omitted to indicate an implicit value of 'identity'.
    pub fn get_key_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_format
    }
    /// Relates to DRM implementation. Either a single positive integer version value or a slash delimited list of version values (1/2/3).
    pub fn key_format_versions(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_format_versions = ::std::option::Option::Some(input.into());
        self
    }
    /// Relates to DRM implementation. Either a single positive integer version value or a slash delimited list of version values (1/2/3).
    pub fn set_key_format_versions(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_format_versions = input;
        self
    }
    /// Relates to DRM implementation. Either a single positive integer version value or a slash delimited list of version values (1/2/3).
    pub fn get_key_format_versions(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_format_versions
    }
    /// Relates to DRM implementation. Use a 32-character hexidecimal string to specify Key Value.
    pub fn static_key_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.static_key_value = ::std::option::Option::Some(input.into());
        self
    }
    /// Relates to DRM implementation. Use a 32-character hexidecimal string to specify Key Value.
    pub fn set_static_key_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.static_key_value = input;
        self
    }
    /// Relates to DRM implementation. Use a 32-character hexidecimal string to specify Key Value.
    pub fn get_static_key_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.static_key_value
    }
    /// Relates to DRM implementation. The location of the license server used for protecting content.
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// Relates to DRM implementation. The location of the license server used for protecting content.
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// Relates to DRM implementation. The location of the license server used for protecting content.
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    /// Consumes the builder and constructs a [`StaticKeyProvider`](crate::types::StaticKeyProvider).
    pub fn build(self) -> crate::types::StaticKeyProvider {
        crate::types::StaticKeyProvider {
            key_format: self.key_format,
            key_format_versions: self.key_format_versions,
            static_key_value: self.static_key_value,
            url: self.url,
        }
    }
}
