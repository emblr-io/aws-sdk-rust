// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDirectConnectGatewayAssociationProposalOutput {
    /// <p>The ID of the associated gateway.</p>
    pub direct_connect_gateway_association_proposal: ::std::option::Option<crate::types::DirectConnectGatewayAssociationProposal>,
    _request_id: Option<String>,
}
impl DeleteDirectConnectGatewayAssociationProposalOutput {
    /// <p>The ID of the associated gateway.</p>
    pub fn direct_connect_gateway_association_proposal(&self) -> ::std::option::Option<&crate::types::DirectConnectGatewayAssociationProposal> {
        self.direct_connect_gateway_association_proposal.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteDirectConnectGatewayAssociationProposalOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteDirectConnectGatewayAssociationProposalOutput {
    /// Creates a new builder-style object to manufacture [`DeleteDirectConnectGatewayAssociationProposalOutput`](crate::operation::delete_direct_connect_gateway_association_proposal::DeleteDirectConnectGatewayAssociationProposalOutput).
    pub fn builder(
    ) -> crate::operation::delete_direct_connect_gateway_association_proposal::builders::DeleteDirectConnectGatewayAssociationProposalOutputBuilder
    {
        crate::operation::delete_direct_connect_gateway_association_proposal::builders::DeleteDirectConnectGatewayAssociationProposalOutputBuilder::default()
    }
}

/// A builder for [`DeleteDirectConnectGatewayAssociationProposalOutput`](crate::operation::delete_direct_connect_gateway_association_proposal::DeleteDirectConnectGatewayAssociationProposalOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDirectConnectGatewayAssociationProposalOutputBuilder {
    pub(crate) direct_connect_gateway_association_proposal: ::std::option::Option<crate::types::DirectConnectGatewayAssociationProposal>,
    _request_id: Option<String>,
}
impl DeleteDirectConnectGatewayAssociationProposalOutputBuilder {
    /// <p>The ID of the associated gateway.</p>
    pub fn direct_connect_gateway_association_proposal(mut self, input: crate::types::DirectConnectGatewayAssociationProposal) -> Self {
        self.direct_connect_gateway_association_proposal = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the associated gateway.</p>
    pub fn set_direct_connect_gateway_association_proposal(
        mut self,
        input: ::std::option::Option<crate::types::DirectConnectGatewayAssociationProposal>,
    ) -> Self {
        self.direct_connect_gateway_association_proposal = input;
        self
    }
    /// <p>The ID of the associated gateway.</p>
    pub fn get_direct_connect_gateway_association_proposal(&self) -> &::std::option::Option<crate::types::DirectConnectGatewayAssociationProposal> {
        &self.direct_connect_gateway_association_proposal
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteDirectConnectGatewayAssociationProposalOutput`](crate::operation::delete_direct_connect_gateway_association_proposal::DeleteDirectConnectGatewayAssociationProposalOutput).
    pub fn build(self) -> crate::operation::delete_direct_connect_gateway_association_proposal::DeleteDirectConnectGatewayAssociationProposalOutput {
        crate::operation::delete_direct_connect_gateway_association_proposal::DeleteDirectConnectGatewayAssociationProposalOutput {
            direct_connect_gateway_association_proposal: self.direct_connect_gateway_association_proposal,
            _request_id: self._request_id,
        }
    }
}
