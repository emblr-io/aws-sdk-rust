// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisableFastLaunchOutput {
    /// <p>The ID of the image for which Windows fast launch was disabled.</p>
    pub image_id: ::std::option::Option<::std::string::String>,
    /// <p>The pre-provisioning resource type that must be cleaned after turning off Windows fast launch for the Windows AMI. Supported values include: <code>snapshot</code>.</p>
    pub resource_type: ::std::option::Option<crate::types::FastLaunchResourceType>,
    /// <p>Parameters that were used for Windows fast launch for the Windows AMI before Windows fast launch was disabled. This informs the clean-up process.</p>
    pub snapshot_configuration: ::std::option::Option<crate::types::FastLaunchSnapshotConfigurationResponse>,
    /// <p>The launch template that was used to launch Windows instances from pre-provisioned snapshots.</p>
    pub launch_template: ::std::option::Option<crate::types::FastLaunchLaunchTemplateSpecificationResponse>,
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch.</p>
    pub max_parallel_launches: ::std::option::Option<i32>,
    /// <p>The owner of the Windows AMI for which Windows fast launch was disabled.</p>
    pub owner_id: ::std::option::Option<::std::string::String>,
    /// <p>The current state of Windows fast launch for the specified Windows AMI.</p>
    pub state: ::std::option::Option<crate::types::FastLaunchStateCode>,
    /// <p>The reason that the state changed for Windows fast launch for the Windows AMI.</p>
    pub state_transition_reason: ::std::option::Option<::std::string::String>,
    /// <p>The time that the state changed for Windows fast launch for the Windows AMI.</p>
    pub state_transition_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DisableFastLaunchOutput {
    /// <p>The ID of the image for which Windows fast launch was disabled.</p>
    pub fn image_id(&self) -> ::std::option::Option<&str> {
        self.image_id.as_deref()
    }
    /// <p>The pre-provisioning resource type that must be cleaned after turning off Windows fast launch for the Windows AMI. Supported values include: <code>snapshot</code>.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::FastLaunchResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>Parameters that were used for Windows fast launch for the Windows AMI before Windows fast launch was disabled. This informs the clean-up process.</p>
    pub fn snapshot_configuration(&self) -> ::std::option::Option<&crate::types::FastLaunchSnapshotConfigurationResponse> {
        self.snapshot_configuration.as_ref()
    }
    /// <p>The launch template that was used to launch Windows instances from pre-provisioned snapshots.</p>
    pub fn launch_template(&self) -> ::std::option::Option<&crate::types::FastLaunchLaunchTemplateSpecificationResponse> {
        self.launch_template.as_ref()
    }
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch.</p>
    pub fn max_parallel_launches(&self) -> ::std::option::Option<i32> {
        self.max_parallel_launches
    }
    /// <p>The owner of the Windows AMI for which Windows fast launch was disabled.</p>
    pub fn owner_id(&self) -> ::std::option::Option<&str> {
        self.owner_id.as_deref()
    }
    /// <p>The current state of Windows fast launch for the specified Windows AMI.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::FastLaunchStateCode> {
        self.state.as_ref()
    }
    /// <p>The reason that the state changed for Windows fast launch for the Windows AMI.</p>
    pub fn state_transition_reason(&self) -> ::std::option::Option<&str> {
        self.state_transition_reason.as_deref()
    }
    /// <p>The time that the state changed for Windows fast launch for the Windows AMI.</p>
    pub fn state_transition_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.state_transition_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DisableFastLaunchOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DisableFastLaunchOutput {
    /// Creates a new builder-style object to manufacture [`DisableFastLaunchOutput`](crate::operation::disable_fast_launch::DisableFastLaunchOutput).
    pub fn builder() -> crate::operation::disable_fast_launch::builders::DisableFastLaunchOutputBuilder {
        crate::operation::disable_fast_launch::builders::DisableFastLaunchOutputBuilder::default()
    }
}

/// A builder for [`DisableFastLaunchOutput`](crate::operation::disable_fast_launch::DisableFastLaunchOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisableFastLaunchOutputBuilder {
    pub(crate) image_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::FastLaunchResourceType>,
    pub(crate) snapshot_configuration: ::std::option::Option<crate::types::FastLaunchSnapshotConfigurationResponse>,
    pub(crate) launch_template: ::std::option::Option<crate::types::FastLaunchLaunchTemplateSpecificationResponse>,
    pub(crate) max_parallel_launches: ::std::option::Option<i32>,
    pub(crate) owner_id: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::FastLaunchStateCode>,
    pub(crate) state_transition_reason: ::std::option::Option<::std::string::String>,
    pub(crate) state_transition_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DisableFastLaunchOutputBuilder {
    /// <p>The ID of the image for which Windows fast launch was disabled.</p>
    pub fn image_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the image for which Windows fast launch was disabled.</p>
    pub fn set_image_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_id = input;
        self
    }
    /// <p>The ID of the image for which Windows fast launch was disabled.</p>
    pub fn get_image_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_id
    }
    /// <p>The pre-provisioning resource type that must be cleaned after turning off Windows fast launch for the Windows AMI. Supported values include: <code>snapshot</code>.</p>
    pub fn resource_type(mut self, input: crate::types::FastLaunchResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The pre-provisioning resource type that must be cleaned after turning off Windows fast launch for the Windows AMI. Supported values include: <code>snapshot</code>.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::FastLaunchResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The pre-provisioning resource type that must be cleaned after turning off Windows fast launch for the Windows AMI. Supported values include: <code>snapshot</code>.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::FastLaunchResourceType> {
        &self.resource_type
    }
    /// <p>Parameters that were used for Windows fast launch for the Windows AMI before Windows fast launch was disabled. This informs the clean-up process.</p>
    pub fn snapshot_configuration(mut self, input: crate::types::FastLaunchSnapshotConfigurationResponse) -> Self {
        self.snapshot_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Parameters that were used for Windows fast launch for the Windows AMI before Windows fast launch was disabled. This informs the clean-up process.</p>
    pub fn set_snapshot_configuration(mut self, input: ::std::option::Option<crate::types::FastLaunchSnapshotConfigurationResponse>) -> Self {
        self.snapshot_configuration = input;
        self
    }
    /// <p>Parameters that were used for Windows fast launch for the Windows AMI before Windows fast launch was disabled. This informs the clean-up process.</p>
    pub fn get_snapshot_configuration(&self) -> &::std::option::Option<crate::types::FastLaunchSnapshotConfigurationResponse> {
        &self.snapshot_configuration
    }
    /// <p>The launch template that was used to launch Windows instances from pre-provisioned snapshots.</p>
    pub fn launch_template(mut self, input: crate::types::FastLaunchLaunchTemplateSpecificationResponse) -> Self {
        self.launch_template = ::std::option::Option::Some(input);
        self
    }
    /// <p>The launch template that was used to launch Windows instances from pre-provisioned snapshots.</p>
    pub fn set_launch_template(mut self, input: ::std::option::Option<crate::types::FastLaunchLaunchTemplateSpecificationResponse>) -> Self {
        self.launch_template = input;
        self
    }
    /// <p>The launch template that was used to launch Windows instances from pre-provisioned snapshots.</p>
    pub fn get_launch_template(&self) -> &::std::option::Option<crate::types::FastLaunchLaunchTemplateSpecificationResponse> {
        &self.launch_template
    }
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch.</p>
    pub fn max_parallel_launches(mut self, input: i32) -> Self {
        self.max_parallel_launches = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch.</p>
    pub fn set_max_parallel_launches(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_parallel_launches = input;
        self
    }
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch.</p>
    pub fn get_max_parallel_launches(&self) -> &::std::option::Option<i32> {
        &self.max_parallel_launches
    }
    /// <p>The owner of the Windows AMI for which Windows fast launch was disabled.</p>
    pub fn owner_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner of the Windows AMI for which Windows fast launch was disabled.</p>
    pub fn set_owner_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_id = input;
        self
    }
    /// <p>The owner of the Windows AMI for which Windows fast launch was disabled.</p>
    pub fn get_owner_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_id
    }
    /// <p>The current state of Windows fast launch for the specified Windows AMI.</p>
    pub fn state(mut self, input: crate::types::FastLaunchStateCode) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current state of Windows fast launch for the specified Windows AMI.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::FastLaunchStateCode>) -> Self {
        self.state = input;
        self
    }
    /// <p>The current state of Windows fast launch for the specified Windows AMI.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::FastLaunchStateCode> {
        &self.state
    }
    /// <p>The reason that the state changed for Windows fast launch for the Windows AMI.</p>
    pub fn state_transition_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state_transition_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason that the state changed for Windows fast launch for the Windows AMI.</p>
    pub fn set_state_transition_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state_transition_reason = input;
        self
    }
    /// <p>The reason that the state changed for Windows fast launch for the Windows AMI.</p>
    pub fn get_state_transition_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.state_transition_reason
    }
    /// <p>The time that the state changed for Windows fast launch for the Windows AMI.</p>
    pub fn state_transition_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.state_transition_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the state changed for Windows fast launch for the Windows AMI.</p>
    pub fn set_state_transition_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.state_transition_time = input;
        self
    }
    /// <p>The time that the state changed for Windows fast launch for the Windows AMI.</p>
    pub fn get_state_transition_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.state_transition_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DisableFastLaunchOutput`](crate::operation::disable_fast_launch::DisableFastLaunchOutput).
    pub fn build(self) -> crate::operation::disable_fast_launch::DisableFastLaunchOutput {
        crate::operation::disable_fast_launch::DisableFastLaunchOutput {
            image_id: self.image_id,
            resource_type: self.resource_type,
            snapshot_configuration: self.snapshot_configuration,
            launch_template: self.launch_template,
            max_parallel_launches: self.max_parallel_launches,
            owner_id: self.owner_id,
            state: self.state,
            state_transition_reason: self.state_transition_reason,
            state_transition_time: self.state_transition_time,
            _request_id: self._request_id,
        }
    }
}
