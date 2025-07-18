// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a <code><code>DeleteInboundCrossClusterSearchConnection</code></code> operation. Contains details of deleted inbound connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteInboundCrossClusterSearchConnectionOutput {
    /// <p>Specifies the <code><code>InboundCrossClusterSearchConnection</code></code> of deleted inbound connection.</p>
    pub cross_cluster_search_connection: ::std::option::Option<crate::types::InboundCrossClusterSearchConnection>,
    _request_id: Option<String>,
}
impl DeleteInboundCrossClusterSearchConnectionOutput {
    /// <p>Specifies the <code><code>InboundCrossClusterSearchConnection</code></code> of deleted inbound connection.</p>
    pub fn cross_cluster_search_connection(&self) -> ::std::option::Option<&crate::types::InboundCrossClusterSearchConnection> {
        self.cross_cluster_search_connection.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteInboundCrossClusterSearchConnectionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteInboundCrossClusterSearchConnectionOutput {
    /// Creates a new builder-style object to manufacture [`DeleteInboundCrossClusterSearchConnectionOutput`](crate::operation::delete_inbound_cross_cluster_search_connection::DeleteInboundCrossClusterSearchConnectionOutput).
    pub fn builder(
    ) -> crate::operation::delete_inbound_cross_cluster_search_connection::builders::DeleteInboundCrossClusterSearchConnectionOutputBuilder {
        crate::operation::delete_inbound_cross_cluster_search_connection::builders::DeleteInboundCrossClusterSearchConnectionOutputBuilder::default()
    }
}

/// A builder for [`DeleteInboundCrossClusterSearchConnectionOutput`](crate::operation::delete_inbound_cross_cluster_search_connection::DeleteInboundCrossClusterSearchConnectionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteInboundCrossClusterSearchConnectionOutputBuilder {
    pub(crate) cross_cluster_search_connection: ::std::option::Option<crate::types::InboundCrossClusterSearchConnection>,
    _request_id: Option<String>,
}
impl DeleteInboundCrossClusterSearchConnectionOutputBuilder {
    /// <p>Specifies the <code><code>InboundCrossClusterSearchConnection</code></code> of deleted inbound connection.</p>
    pub fn cross_cluster_search_connection(mut self, input: crate::types::InboundCrossClusterSearchConnection) -> Self {
        self.cross_cluster_search_connection = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the <code><code>InboundCrossClusterSearchConnection</code></code> of deleted inbound connection.</p>
    pub fn set_cross_cluster_search_connection(mut self, input: ::std::option::Option<crate::types::InboundCrossClusterSearchConnection>) -> Self {
        self.cross_cluster_search_connection = input;
        self
    }
    /// <p>Specifies the <code><code>InboundCrossClusterSearchConnection</code></code> of deleted inbound connection.</p>
    pub fn get_cross_cluster_search_connection(&self) -> &::std::option::Option<crate::types::InboundCrossClusterSearchConnection> {
        &self.cross_cluster_search_connection
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteInboundCrossClusterSearchConnectionOutput`](crate::operation::delete_inbound_cross_cluster_search_connection::DeleteInboundCrossClusterSearchConnectionOutput).
    pub fn build(self) -> crate::operation::delete_inbound_cross_cluster_search_connection::DeleteInboundCrossClusterSearchConnectionOutput {
        crate::operation::delete_inbound_cross_cluster_search_connection::DeleteInboundCrossClusterSearchConnectionOutput {
            cross_cluster_search_connection: self.cross_cluster_search_connection,
            _request_id: self._request_id,
        }
    }
}
