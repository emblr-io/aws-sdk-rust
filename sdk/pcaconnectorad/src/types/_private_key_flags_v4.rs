// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Private key flags for v4 templates specify the client compatibility, if the private key can be exported, if user input is required when using a private key, if an alternate signature algorithm should be used, and if certificates are renewed using the same private key.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PrivateKeyFlagsV4 {
    /// <p>Allows the private key to be exported.</p>
    pub exportable_key: ::std::option::Option<bool>,
    /// <p>Require user input when using the private key for enrollment.</p>
    pub strong_key_protection_required: ::std::option::Option<bool>,
    /// <p>Requires the PKCS #1 v2.1 signature format for certificates. You should verify that your CA, objects, and applications can accept this signature format.</p>
    pub require_alternate_signature_algorithm: ::std::option::Option<bool>,
    /// <p>Renew certificate using the same private key.</p>
    pub require_same_key_renewal: ::std::option::Option<bool>,
    /// <p>Specifies the cryptographic service provider category used to generate private keys. Set to TRUE to use Legacy Cryptographic Service Providers and FALSE to use Key Storage Providers.</p>
    pub use_legacy_provider: ::std::option::Option<bool>,
    /// <p>Defines the minimum client compatibility.</p>
    pub client_version: crate::types::ClientCompatibilityV4,
}
impl PrivateKeyFlagsV4 {
    /// <p>Allows the private key to be exported.</p>
    pub fn exportable_key(&self) -> ::std::option::Option<bool> {
        self.exportable_key
    }
    /// <p>Require user input when using the private key for enrollment.</p>
    pub fn strong_key_protection_required(&self) -> ::std::option::Option<bool> {
        self.strong_key_protection_required
    }
    /// <p>Requires the PKCS #1 v2.1 signature format for certificates. You should verify that your CA, objects, and applications can accept this signature format.</p>
    pub fn require_alternate_signature_algorithm(&self) -> ::std::option::Option<bool> {
        self.require_alternate_signature_algorithm
    }
    /// <p>Renew certificate using the same private key.</p>
    pub fn require_same_key_renewal(&self) -> ::std::option::Option<bool> {
        self.require_same_key_renewal
    }
    /// <p>Specifies the cryptographic service provider category used to generate private keys. Set to TRUE to use Legacy Cryptographic Service Providers and FALSE to use Key Storage Providers.</p>
    pub fn use_legacy_provider(&self) -> ::std::option::Option<bool> {
        self.use_legacy_provider
    }
    /// <p>Defines the minimum client compatibility.</p>
    pub fn client_version(&self) -> &crate::types::ClientCompatibilityV4 {
        &self.client_version
    }
}
impl PrivateKeyFlagsV4 {
    /// Creates a new builder-style object to manufacture [`PrivateKeyFlagsV4`](crate::types::PrivateKeyFlagsV4).
    pub fn builder() -> crate::types::builders::PrivateKeyFlagsV4Builder {
        crate::types::builders::PrivateKeyFlagsV4Builder::default()
    }
}

/// A builder for [`PrivateKeyFlagsV4`](crate::types::PrivateKeyFlagsV4).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PrivateKeyFlagsV4Builder {
    pub(crate) exportable_key: ::std::option::Option<bool>,
    pub(crate) strong_key_protection_required: ::std::option::Option<bool>,
    pub(crate) require_alternate_signature_algorithm: ::std::option::Option<bool>,
    pub(crate) require_same_key_renewal: ::std::option::Option<bool>,
    pub(crate) use_legacy_provider: ::std::option::Option<bool>,
    pub(crate) client_version: ::std::option::Option<crate::types::ClientCompatibilityV4>,
}
impl PrivateKeyFlagsV4Builder {
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
    /// <p>Requires the PKCS #1 v2.1 signature format for certificates. You should verify that your CA, objects, and applications can accept this signature format.</p>
    pub fn require_alternate_signature_algorithm(mut self, input: bool) -> Self {
        self.require_alternate_signature_algorithm = ::std::option::Option::Some(input);
        self
    }
    /// <p>Requires the PKCS #1 v2.1 signature format for certificates. You should verify that your CA, objects, and applications can accept this signature format.</p>
    pub fn set_require_alternate_signature_algorithm(mut self, input: ::std::option::Option<bool>) -> Self {
        self.require_alternate_signature_algorithm = input;
        self
    }
    /// <p>Requires the PKCS #1 v2.1 signature format for certificates. You should verify that your CA, objects, and applications can accept this signature format.</p>
    pub fn get_require_alternate_signature_algorithm(&self) -> &::std::option::Option<bool> {
        &self.require_alternate_signature_algorithm
    }
    /// <p>Renew certificate using the same private key.</p>
    pub fn require_same_key_renewal(mut self, input: bool) -> Self {
        self.require_same_key_renewal = ::std::option::Option::Some(input);
        self
    }
    /// <p>Renew certificate using the same private key.</p>
    pub fn set_require_same_key_renewal(mut self, input: ::std::option::Option<bool>) -> Self {
        self.require_same_key_renewal = input;
        self
    }
    /// <p>Renew certificate using the same private key.</p>
    pub fn get_require_same_key_renewal(&self) -> &::std::option::Option<bool> {
        &self.require_same_key_renewal
    }
    /// <p>Specifies the cryptographic service provider category used to generate private keys. Set to TRUE to use Legacy Cryptographic Service Providers and FALSE to use Key Storage Providers.</p>
    pub fn use_legacy_provider(mut self, input: bool) -> Self {
        self.use_legacy_provider = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the cryptographic service provider category used to generate private keys. Set to TRUE to use Legacy Cryptographic Service Providers and FALSE to use Key Storage Providers.</p>
    pub fn set_use_legacy_provider(mut self, input: ::std::option::Option<bool>) -> Self {
        self.use_legacy_provider = input;
        self
    }
    /// <p>Specifies the cryptographic service provider category used to generate private keys. Set to TRUE to use Legacy Cryptographic Service Providers and FALSE to use Key Storage Providers.</p>
    pub fn get_use_legacy_provider(&self) -> &::std::option::Option<bool> {
        &self.use_legacy_provider
    }
    /// <p>Defines the minimum client compatibility.</p>
    /// This field is required.
    pub fn client_version(mut self, input: crate::types::ClientCompatibilityV4) -> Self {
        self.client_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the minimum client compatibility.</p>
    pub fn set_client_version(mut self, input: ::std::option::Option<crate::types::ClientCompatibilityV4>) -> Self {
        self.client_version = input;
        self
    }
    /// <p>Defines the minimum client compatibility.</p>
    pub fn get_client_version(&self) -> &::std::option::Option<crate::types::ClientCompatibilityV4> {
        &self.client_version
    }
    /// Consumes the builder and constructs a [`PrivateKeyFlagsV4`](crate::types::PrivateKeyFlagsV4).
    /// This method will fail if any of the following fields are not set:
    /// - [`client_version`](crate::types::builders::PrivateKeyFlagsV4Builder::client_version)
    pub fn build(self) -> ::std::result::Result<crate::types::PrivateKeyFlagsV4, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PrivateKeyFlagsV4 {
            exportable_key: self.exportable_key,
            strong_key_protection_required: self.strong_key_protection_required,
            require_alternate_signature_algorithm: self.require_alternate_signature_algorithm,
            require_same_key_renewal: self.require_same_key_renewal,
            use_legacy_provider: self.use_legacy_provider,
            client_version: self.client_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "client_version",
                    "client_version was not specified but it is required when building PrivateKeyFlagsV4",
                )
            })?,
        })
    }
}
