// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListVpcConnectionsOutput {
    /// <p>A <code>VPCConnectionSummaries</code> object that returns a summary of VPC connection objects.</p>
    pub vpc_connection_summaries: ::std::option::Option<::std::vec::Vec<crate::types::VpcConnectionSummary>>,
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    _request_id: Option<String>,
}
impl ListVpcConnectionsOutput {
    /// <p>A <code>VPCConnectionSummaries</code> object that returns a summary of VPC connection objects.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.vpc_connection_summaries.is_none()`.
    pub fn vpc_connection_summaries(&self) -> &[crate::types::VpcConnectionSummary] {
        self.vpc_connection_summaries.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(&self) -> i32 {
        self.status
    }
}
impl ::aws_types::request_id::RequestId for ListVpcConnectionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListVpcConnectionsOutput {
    /// Creates a new builder-style object to manufacture [`ListVpcConnectionsOutput`](crate::operation::list_vpc_connections::ListVpcConnectionsOutput).
    pub fn builder() -> crate::operation::list_vpc_connections::builders::ListVpcConnectionsOutputBuilder {
        crate::operation::list_vpc_connections::builders::ListVpcConnectionsOutputBuilder::default()
    }
}

/// A builder for [`ListVpcConnectionsOutput`](crate::operation::list_vpc_connections::ListVpcConnectionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListVpcConnectionsOutputBuilder {
    pub(crate) vpc_connection_summaries: ::std::option::Option<::std::vec::Vec<crate::types::VpcConnectionSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl ListVpcConnectionsOutputBuilder {
    /// Appends an item to `vpc_connection_summaries`.
    ///
    /// To override the contents of this collection use [`set_vpc_connection_summaries`](Self::set_vpc_connection_summaries).
    ///
    /// <p>A <code>VPCConnectionSummaries</code> object that returns a summary of VPC connection objects.</p>
    pub fn vpc_connection_summaries(mut self, input: crate::types::VpcConnectionSummary) -> Self {
        let mut v = self.vpc_connection_summaries.unwrap_or_default();
        v.push(input);
        self.vpc_connection_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>A <code>VPCConnectionSummaries</code> object that returns a summary of VPC connection objects.</p>
    pub fn set_vpc_connection_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::VpcConnectionSummary>>) -> Self {
        self.vpc_connection_summaries = input;
        self
    }
    /// <p>A <code>VPCConnectionSummaries</code> object that returns a summary of VPC connection objects.</p>
    pub fn get_vpc_connection_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::VpcConnectionSummary>> {
        &self.vpc_connection_summaries
    }
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or null if there are no more results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(mut self, input: i32) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status = input;
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn get_status(&self) -> &::std::option::Option<i32> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListVpcConnectionsOutput`](crate::operation::list_vpc_connections::ListVpcConnectionsOutput).
    pub fn build(self) -> crate::operation::list_vpc_connections::ListVpcConnectionsOutput {
        crate::operation::list_vpc_connections::ListVpcConnectionsOutput {
            vpc_connection_summaries: self.vpc_connection_summaries,
            next_token: self.next_token,
            request_id: self.request_id,
            status: self.status.unwrap_or_default(),
            _request_id: self._request_id,
        }
    }
}
