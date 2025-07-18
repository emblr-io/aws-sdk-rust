// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateTrafficDistributionGroupUserOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DisassociateTrafficDistributionGroupUserOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DisassociateTrafficDistributionGroupUserOutput {
    /// Creates a new builder-style object to manufacture [`DisassociateTrafficDistributionGroupUserOutput`](crate::operation::disassociate_traffic_distribution_group_user::DisassociateTrafficDistributionGroupUserOutput).
    pub fn builder() -> crate::operation::disassociate_traffic_distribution_group_user::builders::DisassociateTrafficDistributionGroupUserOutputBuilder
    {
        crate::operation::disassociate_traffic_distribution_group_user::builders::DisassociateTrafficDistributionGroupUserOutputBuilder::default()
    }
}

/// A builder for [`DisassociateTrafficDistributionGroupUserOutput`](crate::operation::disassociate_traffic_distribution_group_user::DisassociateTrafficDistributionGroupUserOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateTrafficDistributionGroupUserOutputBuilder {
    _request_id: Option<String>,
}
impl DisassociateTrafficDistributionGroupUserOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DisassociateTrafficDistributionGroupUserOutput`](crate::operation::disassociate_traffic_distribution_group_user::DisassociateTrafficDistributionGroupUserOutput).
    pub fn build(self) -> crate::operation::disassociate_traffic_distribution_group_user::DisassociateTrafficDistributionGroupUserOutput {
        crate::operation::disassociate_traffic_distribution_group_user::DisassociateTrafficDistributionGroupUserOutput {
            _request_id: self._request_id,
        }
    }
}
