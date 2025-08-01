// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a static route for a VPN connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VpnStaticRoute {
    /// <p>The CIDR block associated with the local subnet of the customer data center.</p>
    pub destination_cidr_block: ::std::option::Option<::std::string::String>,
    /// <p>Indicates how the routes were provided.</p>
    pub source: ::std::option::Option<crate::types::VpnStaticRouteSource>,
    /// <p>The current state of the static route.</p>
    pub state: ::std::option::Option<crate::types::VpnState>,
}
impl VpnStaticRoute {
    /// <p>The CIDR block associated with the local subnet of the customer data center.</p>
    pub fn destination_cidr_block(&self) -> ::std::option::Option<&str> {
        self.destination_cidr_block.as_deref()
    }
    /// <p>Indicates how the routes were provided.</p>
    pub fn source(&self) -> ::std::option::Option<&crate::types::VpnStaticRouteSource> {
        self.source.as_ref()
    }
    /// <p>The current state of the static route.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::VpnState> {
        self.state.as_ref()
    }
}
impl VpnStaticRoute {
    /// Creates a new builder-style object to manufacture [`VpnStaticRoute`](crate::types::VpnStaticRoute).
    pub fn builder() -> crate::types::builders::VpnStaticRouteBuilder {
        crate::types::builders::VpnStaticRouteBuilder::default()
    }
}

/// A builder for [`VpnStaticRoute`](crate::types::VpnStaticRoute).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VpnStaticRouteBuilder {
    pub(crate) destination_cidr_block: ::std::option::Option<::std::string::String>,
    pub(crate) source: ::std::option::Option<crate::types::VpnStaticRouteSource>,
    pub(crate) state: ::std::option::Option<crate::types::VpnState>,
}
impl VpnStaticRouteBuilder {
    /// <p>The CIDR block associated with the local subnet of the customer data center.</p>
    pub fn destination_cidr_block(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.destination_cidr_block = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The CIDR block associated with the local subnet of the customer data center.</p>
    pub fn set_destination_cidr_block(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.destination_cidr_block = input;
        self
    }
    /// <p>The CIDR block associated with the local subnet of the customer data center.</p>
    pub fn get_destination_cidr_block(&self) -> &::std::option::Option<::std::string::String> {
        &self.destination_cidr_block
    }
    /// <p>Indicates how the routes were provided.</p>
    pub fn source(mut self, input: crate::types::VpnStaticRouteSource) -> Self {
        self.source = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates how the routes were provided.</p>
    pub fn set_source(mut self, input: ::std::option::Option<crate::types::VpnStaticRouteSource>) -> Self {
        self.source = input;
        self
    }
    /// <p>Indicates how the routes were provided.</p>
    pub fn get_source(&self) -> &::std::option::Option<crate::types::VpnStaticRouteSource> {
        &self.source
    }
    /// <p>The current state of the static route.</p>
    pub fn state(mut self, input: crate::types::VpnState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of the static route.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::VpnState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The current state of the static route.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::VpnState> {
        &self.state
    }
    /// Consumes the builder and constructs a [`VpnStaticRoute`](crate::types::VpnStaticRoute).
    pub fn build(self) -> crate::types::VpnStaticRoute {
        crate::types::VpnStaticRoute {
            destination_cidr_block: self.destination_cidr_block,
            source: self.source,
            state: self.state,
        }
    }
}
