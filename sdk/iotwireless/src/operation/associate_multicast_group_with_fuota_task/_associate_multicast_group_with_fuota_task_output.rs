// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateMulticastGroupWithFuotaTaskOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for AssociateMulticastGroupWithFuotaTaskOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateMulticastGroupWithFuotaTaskOutput {
    /// Creates a new builder-style object to manufacture [`AssociateMulticastGroupWithFuotaTaskOutput`](crate::operation::associate_multicast_group_with_fuota_task::AssociateMulticastGroupWithFuotaTaskOutput).
    pub fn builder() -> crate::operation::associate_multicast_group_with_fuota_task::builders::AssociateMulticastGroupWithFuotaTaskOutputBuilder {
        crate::operation::associate_multicast_group_with_fuota_task::builders::AssociateMulticastGroupWithFuotaTaskOutputBuilder::default()
    }
}

/// A builder for [`AssociateMulticastGroupWithFuotaTaskOutput`](crate::operation::associate_multicast_group_with_fuota_task::AssociateMulticastGroupWithFuotaTaskOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateMulticastGroupWithFuotaTaskOutputBuilder {
    _request_id: Option<String>,
}
impl AssociateMulticastGroupWithFuotaTaskOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateMulticastGroupWithFuotaTaskOutput`](crate::operation::associate_multicast_group_with_fuota_task::AssociateMulticastGroupWithFuotaTaskOutput).
    pub fn build(self) -> crate::operation::associate_multicast_group_with_fuota_task::AssociateMulticastGroupWithFuotaTaskOutput {
        crate::operation::associate_multicast_group_with_fuota_task::AssociateMulticastGroupWithFuotaTaskOutput {
            _request_id: self._request_id,
        }
    }
}
