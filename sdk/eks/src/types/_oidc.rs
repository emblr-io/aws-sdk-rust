// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing the <a href="https://openid.net/connect/">OpenID Connect</a> (OIDC) identity provider information for the cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Oidc {
    /// <p>The issuer URL for the OIDC identity provider.</p>
    pub issuer: ::std::option::Option<::std::string::String>,
}
impl Oidc {
    /// <p>The issuer URL for the OIDC identity provider.</p>
    pub fn issuer(&self) -> ::std::option::Option<&str> {
        self.issuer.as_deref()
    }
}
impl Oidc {
    /// Creates a new builder-style object to manufacture [`Oidc`](crate::types::Oidc).
    pub fn builder() -> crate::types::builders::OidcBuilder {
        crate::types::builders::OidcBuilder::default()
    }
}

/// A builder for [`Oidc`](crate::types::Oidc).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OidcBuilder {
    pub(crate) issuer: ::std::option::Option<::std::string::String>,
}
impl OidcBuilder {
    /// <p>The issuer URL for the OIDC identity provider.</p>
    pub fn issuer(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.issuer = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The issuer URL for the OIDC identity provider.</p>
    pub fn set_issuer(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.issuer = input;
        self
    }
    /// <p>The issuer URL for the OIDC identity provider.</p>
    pub fn get_issuer(&self) -> &::std::option::Option<::std::string::String> {
        &self.issuer
    }
    /// Consumes the builder and constructs a [`Oidc`](crate::types::Oidc).
    pub fn build(self) -> crate::types::Oidc {
        crate::types::Oidc { issuer: self.issuer }
    }
}
