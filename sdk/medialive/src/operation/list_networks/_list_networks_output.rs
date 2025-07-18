// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Placeholder documentation for ListNetworksResponse
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListNetworksOutput {
    /// An array of networks that you have created.
    pub networks: ::std::option::Option<::std::vec::Vec<crate::types::DescribeNetworkSummary>>,
    /// Token for the next ListNetworks request.
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListNetworksOutput {
    /// An array of networks that you have created.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.networks.is_none()`.
    pub fn networks(&self) -> &[crate::types::DescribeNetworkSummary] {
        self.networks.as_deref().unwrap_or_default()
    }
    /// Token for the next ListNetworks request.
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListNetworksOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListNetworksOutput {
    /// Creates a new builder-style object to manufacture [`ListNetworksOutput`](crate::operation::list_networks::ListNetworksOutput).
    pub fn builder() -> crate::operation::list_networks::builders::ListNetworksOutputBuilder {
        crate::operation::list_networks::builders::ListNetworksOutputBuilder::default()
    }
}

/// A builder for [`ListNetworksOutput`](crate::operation::list_networks::ListNetworksOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListNetworksOutputBuilder {
    pub(crate) networks: ::std::option::Option<::std::vec::Vec<crate::types::DescribeNetworkSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListNetworksOutputBuilder {
    /// Appends an item to `networks`.
    ///
    /// To override the contents of this collection use [`set_networks`](Self::set_networks).
    ///
    /// An array of networks that you have created.
    pub fn networks(mut self, input: crate::types::DescribeNetworkSummary) -> Self {
        let mut v = self.networks.unwrap_or_default();
        v.push(input);
        self.networks = ::std::option::Option::Some(v);
        self
    }
    /// An array of networks that you have created.
    pub fn set_networks(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DescribeNetworkSummary>>) -> Self {
        self.networks = input;
        self
    }
    /// An array of networks that you have created.
    pub fn get_networks(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DescribeNetworkSummary>> {
        &self.networks
    }
    /// Token for the next ListNetworks request.
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// Token for the next ListNetworks request.
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// Token for the next ListNetworks request.
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListNetworksOutput`](crate::operation::list_networks::ListNetworksOutput).
    pub fn build(self) -> crate::operation::list_networks::ListNetworksOutput {
        crate::operation::list_networks::ListNetworksOutput {
            networks: self.networks,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
