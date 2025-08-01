// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes volume attachment details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetachVolumeOutput {
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub delete_on_termination: ::std::option::Option<bool>,
    /// <p>The ARN of the Amazon ECS or Fargate task to which the volume is attached.</p>
    pub associated_resource: ::std::option::Option<::std::string::String>,
    /// <p>The service principal of Amazon Web Services service that owns the underlying instance to which the volume is attached.</p>
    /// <p>This parameter is returned only for volumes that are attached to Fargate tasks.</p>
    pub instance_owning_service: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the volume.</p>
    pub volume_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the instance.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The device name.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub device: ::std::option::Option<::std::string::String>,
    /// <p>The attachment state of the volume.</p>
    pub state: ::std::option::Option<crate::types::VolumeAttachmentState>,
    /// <p>The time stamp when the attachment initiated.</p>
    pub attach_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DetachVolumeOutput {
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub fn delete_on_termination(&self) -> ::std::option::Option<bool> {
        self.delete_on_termination
    }
    /// <p>The ARN of the Amazon ECS or Fargate task to which the volume is attached.</p>
    pub fn associated_resource(&self) -> ::std::option::Option<&str> {
        self.associated_resource.as_deref()
    }
    /// <p>The service principal of Amazon Web Services service that owns the underlying instance to which the volume is attached.</p>
    /// <p>This parameter is returned only for volumes that are attached to Fargate tasks.</p>
    pub fn instance_owning_service(&self) -> ::std::option::Option<&str> {
        self.instance_owning_service.as_deref()
    }
    /// <p>The ID of the volume.</p>
    pub fn volume_id(&self) -> ::std::option::Option<&str> {
        self.volume_id.as_deref()
    }
    /// <p>The ID of the instance.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The device name.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub fn device(&self) -> ::std::option::Option<&str> {
        self.device.as_deref()
    }
    /// <p>The attachment state of the volume.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::VolumeAttachmentState> {
        self.state.as_ref()
    }
    /// <p>The time stamp when the attachment initiated.</p>
    pub fn attach_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.attach_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DetachVolumeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DetachVolumeOutput {
    /// Creates a new builder-style object to manufacture [`DetachVolumeOutput`](crate::operation::detach_volume::DetachVolumeOutput).
    pub fn builder() -> crate::operation::detach_volume::builders::DetachVolumeOutputBuilder {
        crate::operation::detach_volume::builders::DetachVolumeOutputBuilder::default()
    }
}

/// A builder for [`DetachVolumeOutput`](crate::operation::detach_volume::DetachVolumeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetachVolumeOutputBuilder {
    pub(crate) delete_on_termination: ::std::option::Option<bool>,
    pub(crate) associated_resource: ::std::option::Option<::std::string::String>,
    pub(crate) instance_owning_service: ::std::option::Option<::std::string::String>,
    pub(crate) volume_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) device: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::VolumeAttachmentState>,
    pub(crate) attach_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DetachVolumeOutputBuilder {
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub fn delete_on_termination(mut self, input: bool) -> Self {
        self.delete_on_termination = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub fn set_delete_on_termination(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_on_termination = input;
        self
    }
    /// <p>Indicates whether the EBS volume is deleted on instance termination.</p>
    pub fn get_delete_on_termination(&self) -> &::std::option::Option<bool> {
        &self.delete_on_termination
    }
    /// <p>The ARN of the Amazon ECS or Fargate task to which the volume is attached.</p>
    pub fn associated_resource(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.associated_resource = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Amazon ECS or Fargate task to which the volume is attached.</p>
    pub fn set_associated_resource(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.associated_resource = input;
        self
    }
    /// <p>The ARN of the Amazon ECS or Fargate task to which the volume is attached.</p>
    pub fn get_associated_resource(&self) -> &::std::option::Option<::std::string::String> {
        &self.associated_resource
    }
    /// <p>The service principal of Amazon Web Services service that owns the underlying instance to which the volume is attached.</p>
    /// <p>This parameter is returned only for volumes that are attached to Fargate tasks.</p>
    pub fn instance_owning_service(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_owning_service = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The service principal of Amazon Web Services service that owns the underlying instance to which the volume is attached.</p>
    /// <p>This parameter is returned only for volumes that are attached to Fargate tasks.</p>
    pub fn set_instance_owning_service(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_owning_service = input;
        self
    }
    /// <p>The service principal of Amazon Web Services service that owns the underlying instance to which the volume is attached.</p>
    /// <p>This parameter is returned only for volumes that are attached to Fargate tasks.</p>
    pub fn get_instance_owning_service(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_owning_service
    }
    /// <p>The ID of the volume.</p>
    pub fn volume_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.volume_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the volume.</p>
    pub fn set_volume_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.volume_id = input;
        self
    }
    /// <p>The ID of the volume.</p>
    pub fn get_volume_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.volume_id
    }
    /// <p>The ID of the instance.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the instance.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the instance.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The device name.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub fn device(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.device = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The device name.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub fn set_device(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.device = input;
        self
    }
    /// <p>The device name.</p>
    /// <p>If the volume is attached to a Fargate task, this parameter returns <code>null</code>.</p>
    pub fn get_device(&self) -> &::std::option::Option<::std::string::String> {
        &self.device
    }
    /// <p>The attachment state of the volume.</p>
    pub fn state(mut self, input: crate::types::VolumeAttachmentState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The attachment state of the volume.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::VolumeAttachmentState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The attachment state of the volume.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::VolumeAttachmentState> {
        &self.state
    }
    /// <p>The time stamp when the attachment initiated.</p>
    pub fn attach_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.attach_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time stamp when the attachment initiated.</p>
    pub fn set_attach_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.attach_time = input;
        self
    }
    /// <p>The time stamp when the attachment initiated.</p>
    pub fn get_attach_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.attach_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DetachVolumeOutput`](crate::operation::detach_volume::DetachVolumeOutput).
    pub fn build(self) -> crate::operation::detach_volume::DetachVolumeOutput {
        crate::operation::detach_volume::DetachVolumeOutput {
            delete_on_termination: self.delete_on_termination,
            associated_resource: self.associated_resource,
            instance_owning_service: self.instance_owning_service,
            volume_id: self.volume_id,
            instance_id: self.instance_id,
            device: self.device,
            state: self.state,
            attach_time: self.attach_time,
            _request_id: self._request_id,
        }
    }
}
