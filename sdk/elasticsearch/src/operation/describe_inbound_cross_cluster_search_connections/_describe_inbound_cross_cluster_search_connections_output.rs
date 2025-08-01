// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a <code><code>DescribeInboundCrossClusterSearchConnections</code></code> request. Contains the list of connections matching the filter criteria.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeInboundCrossClusterSearchConnectionsOutput {
    /// <p>Consists of list of <code><code>InboundCrossClusterSearchConnection</code></code> matching the specified filter criteria.</p>
    pub cross_cluster_search_connections: ::std::option::Option<::std::vec::Vec<crate::types::InboundCrossClusterSearchConnection>>,
    /// <p>If more results are available and NextToken is present, make the next request to the same API with the received NextToken to paginate the remaining results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeInboundCrossClusterSearchConnectionsOutput {
    /// <p>Consists of list of <code><code>InboundCrossClusterSearchConnection</code></code> matching the specified filter criteria.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cross_cluster_search_connections.is_none()`.
    pub fn cross_cluster_search_connections(&self) -> &[crate::types::InboundCrossClusterSearchConnection] {
        self.cross_cluster_search_connections.as_deref().unwrap_or_default()
    }
    /// <p>If more results are available and NextToken is present, make the next request to the same API with the received NextToken to paginate the remaining results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeInboundCrossClusterSearchConnectionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeInboundCrossClusterSearchConnectionsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeInboundCrossClusterSearchConnectionsOutput`](crate::operation::describe_inbound_cross_cluster_search_connections::DescribeInboundCrossClusterSearchConnectionsOutput).
    pub fn builder(
    ) -> crate::operation::describe_inbound_cross_cluster_search_connections::builders::DescribeInboundCrossClusterSearchConnectionsOutputBuilder
    {
        crate::operation::describe_inbound_cross_cluster_search_connections::builders::DescribeInboundCrossClusterSearchConnectionsOutputBuilder::default()
    }
}

/// A builder for [`DescribeInboundCrossClusterSearchConnectionsOutput`](crate::operation::describe_inbound_cross_cluster_search_connections::DescribeInboundCrossClusterSearchConnectionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeInboundCrossClusterSearchConnectionsOutputBuilder {
    pub(crate) cross_cluster_search_connections: ::std::option::Option<::std::vec::Vec<crate::types::InboundCrossClusterSearchConnection>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeInboundCrossClusterSearchConnectionsOutputBuilder {
    /// Appends an item to `cross_cluster_search_connections`.
    ///
    /// To override the contents of this collection use [`set_cross_cluster_search_connections`](Self::set_cross_cluster_search_connections).
    ///
    /// <p>Consists of list of <code><code>InboundCrossClusterSearchConnection</code></code> matching the specified filter criteria.</p>
    pub fn cross_cluster_search_connections(mut self, input: crate::types::InboundCrossClusterSearchConnection) -> Self {
        let mut v = self.cross_cluster_search_connections.unwrap_or_default();
        v.push(input);
        self.cross_cluster_search_connections = ::std::option::Option::Some(v);
        self
    }
    /// <p>Consists of list of <code><code>InboundCrossClusterSearchConnection</code></code> matching the specified filter criteria.</p>
    pub fn set_cross_cluster_search_connections(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::InboundCrossClusterSearchConnection>>,
    ) -> Self {
        self.cross_cluster_search_connections = input;
        self
    }
    /// <p>Consists of list of <code><code>InboundCrossClusterSearchConnection</code></code> matching the specified filter criteria.</p>
    pub fn get_cross_cluster_search_connections(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::InboundCrossClusterSearchConnection>> {
        &self.cross_cluster_search_connections
    }
    /// <p>If more results are available and NextToken is present, make the next request to the same API with the received NextToken to paginate the remaining results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If more results are available and NextToken is present, make the next request to the same API with the received NextToken to paginate the remaining results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If more results are available and NextToken is present, make the next request to the same API with the received NextToken to paginate the remaining results.</p>
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
    /// Consumes the builder and constructs a [`DescribeInboundCrossClusterSearchConnectionsOutput`](crate::operation::describe_inbound_cross_cluster_search_connections::DescribeInboundCrossClusterSearchConnectionsOutput).
    pub fn build(self) -> crate::operation::describe_inbound_cross_cluster_search_connections::DescribeInboundCrossClusterSearchConnectionsOutput {
        crate::operation::describe_inbound_cross_cluster_search_connections::DescribeInboundCrossClusterSearchConnectionsOutput {
            cross_cluster_search_connections: self.cross_cluster_search_connections,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
