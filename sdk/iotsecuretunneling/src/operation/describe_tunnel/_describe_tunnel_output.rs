// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeTunnelOutput {
    /// <p>The tunnel being described.</p>
    pub tunnel: ::std::option::Option<crate::types::Tunnel>,
    _request_id: Option<String>,
}
impl DescribeTunnelOutput {
    /// <p>The tunnel being described.</p>
    pub fn tunnel(&self) -> ::std::option::Option<&crate::types::Tunnel> {
        self.tunnel.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeTunnelOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeTunnelOutput {
    /// Creates a new builder-style object to manufacture [`DescribeTunnelOutput`](crate::operation::describe_tunnel::DescribeTunnelOutput).
    pub fn builder() -> crate::operation::describe_tunnel::builders::DescribeTunnelOutputBuilder {
        crate::operation::describe_tunnel::builders::DescribeTunnelOutputBuilder::default()
    }
}

/// A builder for [`DescribeTunnelOutput`](crate::operation::describe_tunnel::DescribeTunnelOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeTunnelOutputBuilder {
    pub(crate) tunnel: ::std::option::Option<crate::types::Tunnel>,
    _request_id: Option<String>,
}
impl DescribeTunnelOutputBuilder {
    /// <p>The tunnel being described.</p>
    pub fn tunnel(mut self, input: crate::types::Tunnel) -> Self {
        self.tunnel = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tunnel being described.</p>
    pub fn set_tunnel(mut self, input: ::std::option::Option<crate::types::Tunnel>) -> Self {
        self.tunnel = input;
        self
    }
    /// <p>The tunnel being described.</p>
    pub fn get_tunnel(&self) -> &::std::option::Option<crate::types::Tunnel> {
        &self.tunnel
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeTunnelOutput`](crate::operation::describe_tunnel::DescribeTunnelOutput).
    pub fn build(self) -> crate::operation::describe_tunnel::DescribeTunnelOutput {
        crate::operation::describe_tunnel::DescribeTunnelOutput {
            tunnel: self.tunnel,
            _request_id: self._request_id,
        }
    }
}
