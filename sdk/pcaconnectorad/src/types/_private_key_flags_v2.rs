// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Private key flags for v2 templates specify the client compatibility, if the private key can be exported, and if user input is required when using a private key.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PrivateKeyFlagsV2 {
    /// <p>Allows the private key to be exported.</p>
    pub exportable_key: ::std::option::Option<bool>,
    /// <p>Require user input when using the private key for enrollment.</p>
    pub strong_key_protection_required: ::std::option::Option<bool>,
    /// <p>Defines the minimum client compatibility.</p>
    pub client_version: crate::types::ClientCompatibilityV2,
}
impl PrivateKeyFlagsV2 {
    /// <p>Allows the private key to be exported.</p>
    pub fn exportable_key(&self) -> ::std::option::Option<bool> {
        self.exportable_key
    }
    /// <p>Require user input when using the private key for enrollment.</p>
    pub fn strong_key_protection_required(&self) -> ::std::option::Option<bool> {
        self.strong_key_protection_required
    }
    /// <p>Defines the minimum client compatibility.</p>
    pub fn client_version(&self) -> &crate::types::ClientCompatibilityV2 {
        &self.client_version
    }
}
impl PrivateKeyFlagsV2 {
    /// Creates a new builder-style object to manufacture [`PrivateKeyFlagsV2`](crate::types::PrivateKeyFlagsV2).
    pub fn builder() -> crate::types::builders::PrivateKeyFlagsV2Builder {
        crate::types::builders::PrivateKeyFlagsV2Builder::default()
    }
}

/// A builder for [`PrivateKeyFlagsV2`](crate::types::PrivateKeyFlagsV2).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PrivateKeyFlagsV2Builder {
    pub(crate) exportable_key: ::std::option::Option<bool>,
    pub(crate) strong_key_protection_required: ::std::option::Option<bool>,
    pub(crate) client_version: ::std::option::Option<crate::types::ClientCompatibilityV2>,
}
impl PrivateKeyFlagsV2Builder {
    /// <p>Allows the private key to be exported.</p>
    pub fn exportable_key(mut self, input: bool) -> Self {
        self.exportable_key = ::std::option::Option::Some(input);
        self
    }
    /// <p>Allows the private key to be exported.</p>
    pub fn set_exportable_key(mut self, input: ::std::option::Option<bool>) -> Self {
        self.exportable_key = input;
        self
    }
    /// <p>Allows the private key to be exported.</p>
    pub fn get_exportable_key(&self) -> &::std::option::Option<bool> {
        &self.exportable_key
    }
    /// <p>Require user input when using the private key for enrollment.</p>
    pub fn strong_key_protection_required(mut self, input: bool) -> Self {
        self.strong_key_protection_required = ::std::option::Option::Some(input);
        self
    }
    /// <p>Require user input when using the private key for enrollment.</p>
    pub fn set_strong_key_protection_required(mut self, input: ::std::option::Option<bool>) -> Self {
        self.strong_key_protection_required = input;
        self
    }
    /// <p>Require user input when using the private key for enrollment.</p>
    pub fn get_strong_key_protection_required(&self) -> &::std::option::Option<bool> {
        &self.strong_key_protection_required
    }
    /// <p>Defines the minimum client compatibility.</p>
    /// This field is required.
    pub fn client_version(mut self, input: crate::types::ClientCompatibilityV2) -> Self {
        self.client_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the minimum client compatibility.</p>
    pub fn set_client_version(mut self, input: ::std::option::Option<crate::types::ClientCompatibilityV2>) -> Self {
        self.client_version = input;
        self
    }
    /// <p>Defines the minimum client compatibility.</p>
    pub fn get_client_version(&self) -> &::std::option::Option<crate::types::ClientCompatibilityV2> {
        &self.client_version
    }
    /// Consumes the builder and constructs a [`PrivateKeyFlagsV2`](crate::types::PrivateKeyFlagsV2).
    /// This method will fail if any of the following fields are not set:
    /// - [`client_version`](crate::types::builders::PrivateKeyFlagsV2Builder::client_version)
    pub fn build(self) -> ::std::result::Result<crate::types::PrivateKeyFlagsV2, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PrivateKeyFlagsV2 {
            exportable_key: self.exportable_key,
            strong_key_protection_required: self.strong_key_protection_required,
            client_version: self.client_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "client_version",
                    "client_version was not specified but it is required when building PrivateKeyFlagsV2",
                )
            })?,
        })
    }
}
