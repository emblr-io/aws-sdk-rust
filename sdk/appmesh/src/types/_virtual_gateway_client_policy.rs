// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a client policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualGatewayClientPolicy {
    /// <p>A reference to an object that represents a Transport Layer Security (TLS) client policy.</p>
    pub tls: ::std::option::Option<crate::types::VirtualGatewayClientPolicyTls>,
}
impl VirtualGatewayClientPolicy {
    /// <p>A reference to an object that represents a Transport Layer Security (TLS) client policy.</p>
    pub fn tls(&self) -> ::std::option::Option<&crate::types::VirtualGatewayClientPolicyTls> {
        self.tls.as_ref()
    }
}
impl VirtualGatewayClientPolicy {
    /// Creates a new builder-style object to manufacture [`VirtualGatewayClientPolicy`](crate::types::VirtualGatewayClientPolicy).
    pub fn builder() -> crate::types::builders::VirtualGatewayClientPolicyBuilder {
        crate::types::builders::VirtualGatewayClientPolicyBuilder::default()
    }
}

/// A builder for [`VirtualGatewayClientPolicy`](crate::types::VirtualGatewayClientPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualGatewayClientPolicyBuilder {
    pub(crate) tls: ::std::option::Option<crate::types::VirtualGatewayClientPolicyTls>,
}
impl VirtualGatewayClientPolicyBuilder {
    /// <p>A reference to an object that represents a Transport Layer Security (TLS) client policy.</p>
    pub fn tls(mut self, input: crate::types::VirtualGatewayClientPolicyTls) -> Self {
        self.tls = ::std::option::Option::Some(input);
        self
    }
    /// <p>A reference to an object that represents a Transport Layer Security (TLS) client policy.</p>
    pub fn set_tls(mut self, input: ::std::option::Option<crate::types::VirtualGatewayClientPolicyTls>) -> Self {
        self.tls = input;
        self
    }
    /// <p>A reference to an object that represents a Transport Layer Security (TLS) client policy.</p>
    pub fn get_tls(&self) -> &::std::option::Option<crate::types::VirtualGatewayClientPolicyTls> {
        &self.tls
    }
    /// Consumes the builder and constructs a [`VirtualGatewayClientPolicy`](crate::types::VirtualGatewayClientPolicy).
    pub fn build(self) -> crate::types::VirtualGatewayClientPolicy {
        crate::types::VirtualGatewayClientPolicy { tls: self.tls }
    }
}
