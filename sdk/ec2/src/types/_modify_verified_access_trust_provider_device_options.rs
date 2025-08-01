// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Modifies the configuration of the specified device-based Amazon Web Services Verified Access trust provider.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyVerifiedAccessTrustProviderDeviceOptions {
    /// <p>The URL Amazon Web Services Verified Access will use to verify the authenticity of the device tokens.</p>
    pub public_signing_key_url: ::std::option::Option<::std::string::String>,
}
impl ModifyVerifiedAccessTrustProviderDeviceOptions {
    /// <p>The URL Amazon Web Services Verified Access will use to verify the authenticity of the device tokens.</p>
    pub fn public_signing_key_url(&self) -> ::std::option::Option<&str> {
        self.public_signing_key_url.as_deref()
    }
}
impl ModifyVerifiedAccessTrustProviderDeviceOptions {
    /// Creates a new builder-style object to manufacture [`ModifyVerifiedAccessTrustProviderDeviceOptions`](crate::types::ModifyVerifiedAccessTrustProviderDeviceOptions).
    pub fn builder() -> crate::types::builders::ModifyVerifiedAccessTrustProviderDeviceOptionsBuilder {
        crate::types::builders::ModifyVerifiedAccessTrustProviderDeviceOptionsBuilder::default()
    }
}

/// A builder for [`ModifyVerifiedAccessTrustProviderDeviceOptions`](crate::types::ModifyVerifiedAccessTrustProviderDeviceOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyVerifiedAccessTrustProviderDeviceOptionsBuilder {
    pub(crate) public_signing_key_url: ::std::option::Option<::std::string::String>,
}
impl ModifyVerifiedAccessTrustProviderDeviceOptionsBuilder {
    /// <p>The URL Amazon Web Services Verified Access will use to verify the authenticity of the device tokens.</p>
    pub fn public_signing_key_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_signing_key_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL Amazon Web Services Verified Access will use to verify the authenticity of the device tokens.</p>
    pub fn set_public_signing_key_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_signing_key_url = input;
        self
    }
    /// <p>The URL Amazon Web Services Verified Access will use to verify the authenticity of the device tokens.</p>
    pub fn get_public_signing_key_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_signing_key_url
    }
    /// Consumes the builder and constructs a [`ModifyVerifiedAccessTrustProviderDeviceOptions`](crate::types::ModifyVerifiedAccessTrustProviderDeviceOptions).
    pub fn build(self) -> crate::types::ModifyVerifiedAccessTrustProviderDeviceOptions {
        crate::types::ModifyVerifiedAccessTrustProviderDeviceOptions {
            public_signing_key_url: self.public_signing_key_url,
        }
    }
}
