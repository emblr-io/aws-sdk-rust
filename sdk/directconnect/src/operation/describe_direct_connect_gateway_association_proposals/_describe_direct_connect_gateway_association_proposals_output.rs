// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDirectConnectGatewayAssociationProposalsOutput {
    /// <p>Describes the Direct Connect gateway association proposals.</p>
    pub direct_connect_gateway_association_proposals: ::std::option::Option<::std::vec::Vec<crate::types::DirectConnectGatewayAssociationProposal>>,
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeDirectConnectGatewayAssociationProposalsOutput {
    /// <p>Describes the Direct Connect gateway association proposals.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.direct_connect_gateway_association_proposals.is_none()`.
    pub fn direct_connect_gateway_association_proposals(&self) -> &[crate::types::DirectConnectGatewayAssociationProposal] {
        self.direct_connect_gateway_association_proposals.as_deref().unwrap_or_default()
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDirectConnectGatewayAssociationProposalsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDirectConnectGatewayAssociationProposalsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDirectConnectGatewayAssociationProposalsOutput`](crate::operation::describe_direct_connect_gateway_association_proposals::DescribeDirectConnectGatewayAssociationProposalsOutput).
    pub fn builder() -> crate::operation::describe_direct_connect_gateway_association_proposals::builders::DescribeDirectConnectGatewayAssociationProposalsOutputBuilder{
        crate::operation::describe_direct_connect_gateway_association_proposals::builders::DescribeDirectConnectGatewayAssociationProposalsOutputBuilder::default()
    }
}

/// A builder for [`DescribeDirectConnectGatewayAssociationProposalsOutput`](crate::operation::describe_direct_connect_gateway_association_proposals::DescribeDirectConnectGatewayAssociationProposalsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDirectConnectGatewayAssociationProposalsOutputBuilder {
    pub(crate) direct_connect_gateway_association_proposals:
        ::std::option::Option<::std::vec::Vec<crate::types::DirectConnectGatewayAssociationProposal>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeDirectConnectGatewayAssociationProposalsOutputBuilder {
    /// Appends an item to `direct_connect_gateway_association_proposals`.
    ///
    /// To override the contents of this collection use [`set_direct_connect_gateway_association_proposals`](Self::set_direct_connect_gateway_association_proposals).
    ///
    /// <p>Describes the Direct Connect gateway association proposals.</p>
    pub fn direct_connect_gateway_association_proposals(mut self, input: crate::types::DirectConnectGatewayAssociationProposal) -> Self {
        let mut v = self.direct_connect_gateway_association_proposals.unwrap_or_default();
        v.push(input);
        self.direct_connect_gateway_association_proposals = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the Direct Connect gateway association proposals.</p>
    pub fn set_direct_connect_gateway_association_proposals(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DirectConnectGatewayAssociationProposal>>,
    ) -> Self {
        self.direct_connect_gateway_association_proposals = input;
        self
    }
    /// <p>Describes the Direct Connect gateway association proposals.</p>
    pub fn get_direct_connect_gateway_association_proposals(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<crate::types::DirectConnectGatewayAssociationProposal>> {
        &self.direct_connect_gateway_association_proposals
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`DescribeDirectConnectGatewayAssociationProposalsOutput`](crate::operation::describe_direct_connect_gateway_association_proposals::DescribeDirectConnectGatewayAssociationProposalsOutput).
    pub fn build(
        self,
    ) -> crate::operation::describe_direct_connect_gateway_association_proposals::DescribeDirectConnectGatewayAssociationProposalsOutput {
        crate::operation::describe_direct_connect_gateway_association_proposals::DescribeDirectConnectGatewayAssociationProposalsOutput {
            direct_connect_gateway_association_proposals: self.direct_connect_gateway_association_proposals,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
