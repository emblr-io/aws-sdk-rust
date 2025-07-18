// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateDelegateMacVolumeOwnershipTaskOutput {
    /// <p>Information about the volume ownership delegation task.</p>
    pub mac_modification_task: ::std::option::Option<crate::types::MacModificationTask>,
    _request_id: Option<String>,
}
impl CreateDelegateMacVolumeOwnershipTaskOutput {
    /// <p>Information about the volume ownership delegation task.</p>
    pub fn mac_modification_task(&self) -> ::std::option::Option<&crate::types::MacModificationTask> {
        self.mac_modification_task.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateDelegateMacVolumeOwnershipTaskOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateDelegateMacVolumeOwnershipTaskOutput {
    /// Creates a new builder-style object to manufacture [`CreateDelegateMacVolumeOwnershipTaskOutput`](crate::operation::create_delegate_mac_volume_ownership_task::CreateDelegateMacVolumeOwnershipTaskOutput).
    pub fn builder() -> crate::operation::create_delegate_mac_volume_ownership_task::builders::CreateDelegateMacVolumeOwnershipTaskOutputBuilder {
        crate::operation::create_delegate_mac_volume_ownership_task::builders::CreateDelegateMacVolumeOwnershipTaskOutputBuilder::default()
    }
}

/// A builder for [`CreateDelegateMacVolumeOwnershipTaskOutput`](crate::operation::create_delegate_mac_volume_ownership_task::CreateDelegateMacVolumeOwnershipTaskOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateDelegateMacVolumeOwnershipTaskOutputBuilder {
    pub(crate) mac_modification_task: ::std::option::Option<crate::types::MacModificationTask>,
    _request_id: Option<String>,
}
impl CreateDelegateMacVolumeOwnershipTaskOutputBuilder {
    /// <p>Information about the volume ownership delegation task.</p>
    pub fn mac_modification_task(mut self, input: crate::types::MacModificationTask) -> Self {
        self.mac_modification_task = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the volume ownership delegation task.</p>
    pub fn set_mac_modification_task(mut self, input: ::std::option::Option<crate::types::MacModificationTask>) -> Self {
        self.mac_modification_task = input;
        self
    }
    /// <p>Information about the volume ownership delegation task.</p>
    pub fn get_mac_modification_task(&self) -> &::std::option::Option<crate::types::MacModificationTask> {
        &self.mac_modification_task
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateDelegateMacVolumeOwnershipTaskOutput`](crate::operation::create_delegate_mac_volume_ownership_task::CreateDelegateMacVolumeOwnershipTaskOutput).
    pub fn build(self) -> crate::operation::create_delegate_mac_volume_ownership_task::CreateDelegateMacVolumeOwnershipTaskOutput {
        crate::operation::create_delegate_mac_volume_ownership_task::CreateDelegateMacVolumeOwnershipTaskOutput {
            mac_modification_task: self.mac_modification_task,
            _request_id: self._request_id,
        }
    }
}
