// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies whether the domain should encrypt data at rest, and if so, the Key Management Service (KMS) key to use. Can only be used when creating a new domain or enabling encryption at rest for the first time on an existing domain. You can't modify this parameter after it's already been specified.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EncryptionAtRestOptions {
    /// <p>True to enable encryption at rest.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>The KMS key ID. Takes the form <code>1a2a3a4-1a2a-3a4a-5a6a-1a2a3a4a5a6a</code>.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
}
impl EncryptionAtRestOptions {
    /// <p>True to enable encryption at rest.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>The KMS key ID. Takes the form <code>1a2a3a4-1a2a-3a4a-5a6a-1a2a3a4a5a6a</code>.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
}
impl EncryptionAtRestOptions {
    /// Creates a new builder-style object to manufacture [`EncryptionAtRestOptions`](crate::types::EncryptionAtRestOptions).
    pub fn builder() -> crate::types::builders::EncryptionAtRestOptionsBuilder {
        crate::types::builders::EncryptionAtRestOptionsBuilder::default()
    }
}

/// A builder for [`EncryptionAtRestOptions`](crate::types::EncryptionAtRestOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EncryptionAtRestOptionsBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
}
impl EncryptionAtRestOptionsBuilder {
    /// <p>True to enable encryption at rest.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>True to enable encryption at rest.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>True to enable encryption at rest.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>The KMS key ID. Takes the form <code>1a2a3a4-1a2a-3a4a-5a6a-1a2a3a4a5a6a</code>.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The KMS key ID. Takes the form <code>1a2a3a4-1a2a-3a4a-5a6a-1a2a3a4a5a6a</code>.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The KMS key ID. Takes the form <code>1a2a3a4-1a2a-3a4a-5a6a-1a2a3a4a5a6a</code>.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Consumes the builder and constructs a [`EncryptionAtRestOptions`](crate::types::EncryptionAtRestOptions).
    pub fn build(self) -> crate::types::EncryptionAtRestOptions {
        crate::types::EncryptionAtRestOptions {
            enabled: self.enabled,
            kms_key_id: self.kms_key_id,
        }
    }
}
