// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The current status of Bidirectional Forwarding Detection (BFD) for a BGP session.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RouteServerBfdStatus {
    /// <p>The operational status of the BFD session.</p>
    pub status: ::std::option::Option<crate::types::RouteServerBfdState>,
}
impl RouteServerBfdStatus {
    /// <p>The operational status of the BFD session.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::RouteServerBfdState> {
        self.status.as_ref()
    }
}
impl RouteServerBfdStatus {
    /// Creates a new builder-style object to manufacture [`RouteServerBfdStatus`](crate::types::RouteServerBfdStatus).
    pub fn builder() -> crate::types::builders::RouteServerBfdStatusBuilder {
        crate::types::builders::RouteServerBfdStatusBuilder::default()
    }
}

/// A builder for [`RouteServerBfdStatus`](crate::types::RouteServerBfdStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RouteServerBfdStatusBuilder {
    pub(crate) status: ::std::option::Option<crate::types::RouteServerBfdState>,
}
impl RouteServerBfdStatusBuilder {
    /// <p>The operational status of the BFD session.</p>
    pub fn status(mut self, input: crate::types::RouteServerBfdState) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operational status of the BFD session.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::RouteServerBfdState>) -> Self {
        self.status = input;
        self
    }
    /// <p>The operational status of the BFD session.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::RouteServerBfdState> {
        &self.status
    }
    /// Consumes the builder and constructs a [`RouteServerBfdStatus`](crate::types::RouteServerBfdStatus).
    pub fn build(self) -> crate::types::RouteServerBfdStatus {
        crate::types::RouteServerBfdStatus { status: self.status }
    }
}
