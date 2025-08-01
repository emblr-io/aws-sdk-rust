// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnableFastLaunchInput {
    /// <p>Specify the ID of the image for which to enable Windows fast launch.</p>
    pub image_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of resource to use for pre-provisioning the AMI for Windows fast launch. Supported values include: <code>snapshot</code>, which is the default value.</p>
    pub resource_type: ::std::option::Option<::std::string::String>,
    /// <p>Configuration settings for creating and managing the snapshots that are used for pre-provisioning the AMI for Windows fast launch. The associated <code>ResourceType</code> must be <code>snapshot</code>.</p>
    pub snapshot_configuration: ::std::option::Option<crate::types::FastLaunchSnapshotConfigurationRequest>,
    /// <p>The launch template to use when launching Windows instances from pre-provisioned snapshots. Launch template parameters can include either the name or ID of the launch template, but not both.</p>
    pub launch_template: ::std::option::Option<crate::types::FastLaunchLaunchTemplateSpecificationRequest>,
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch. Value must be <code>6</code> or greater.</p>
    pub max_parallel_launches: ::std::option::Option<i32>,
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub dry_run: ::std::option::Option<bool>,
}
impl EnableFastLaunchInput {
    /// <p>Specify the ID of the image for which to enable Windows fast launch.</p>
    pub fn image_id(&self) -> ::std::option::Option<&str> {
        self.image_id.as_deref()
    }
    /// <p>The type of resource to use for pre-provisioning the AMI for Windows fast launch. Supported values include: <code>snapshot</code>, which is the default value.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&str> {
        self.resource_type.as_deref()
    }
    /// <p>Configuration settings for creating and managing the snapshots that are used for pre-provisioning the AMI for Windows fast launch. The associated <code>ResourceType</code> must be <code>snapshot</code>.</p>
    pub fn snapshot_configuration(&self) -> ::std::option::Option<&crate::types::FastLaunchSnapshotConfigurationRequest> {
        self.snapshot_configuration.as_ref()
    }
    /// <p>The launch template to use when launching Windows instances from pre-provisioned snapshots. Launch template parameters can include either the name or ID of the launch template, but not both.</p>
    pub fn launch_template(&self) -> ::std::option::Option<&crate::types::FastLaunchLaunchTemplateSpecificationRequest> {
        self.launch_template.as_ref()
    }
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch. Value must be <code>6</code> or greater.</p>
    pub fn max_parallel_launches(&self) -> ::std::option::Option<i32> {
        self.max_parallel_launches
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(&self) -> ::std::option::Option<bool> {
        self.dry_run
    }
}
impl EnableFastLaunchInput {
    /// Creates a new builder-style object to manufacture [`EnableFastLaunchInput`](crate::operation::enable_fast_launch::EnableFastLaunchInput).
    pub fn builder() -> crate::operation::enable_fast_launch::builders::EnableFastLaunchInputBuilder {
        crate::operation::enable_fast_launch::builders::EnableFastLaunchInputBuilder::default()
    }
}

/// A builder for [`EnableFastLaunchInput`](crate::operation::enable_fast_launch::EnableFastLaunchInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnableFastLaunchInputBuilder {
    pub(crate) image_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) snapshot_configuration: ::std::option::Option<crate::types::FastLaunchSnapshotConfigurationRequest>,
    pub(crate) launch_template: ::std::option::Option<crate::types::FastLaunchLaunchTemplateSpecificationRequest>,
    pub(crate) max_parallel_launches: ::std::option::Option<i32>,
    pub(crate) dry_run: ::std::option::Option<bool>,
}
impl EnableFastLaunchInputBuilder {
    /// <p>Specify the ID of the image for which to enable Windows fast launch.</p>
    /// This field is required.
    pub fn image_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify the ID of the image for which to enable Windows fast launch.</p>
    pub fn set_image_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_id = input;
        self
    }
    /// <p>Specify the ID of the image for which to enable Windows fast launch.</p>
    pub fn get_image_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_id
    }
    /// <p>The type of resource to use for pre-provisioning the AMI for Windows fast launch. Supported values include: <code>snapshot</code>, which is the default value.</p>
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of resource to use for pre-provisioning the AMI for Windows fast launch. Supported values include: <code>snapshot</code>, which is the default value.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of resource to use for pre-provisioning the AMI for Windows fast launch. Supported values include: <code>snapshot</code>, which is the default value.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// <p>Configuration settings for creating and managing the snapshots that are used for pre-provisioning the AMI for Windows fast launch. The associated <code>ResourceType</code> must be <code>snapshot</code>.</p>
    pub fn snapshot_configuration(mut self, input: crate::types::FastLaunchSnapshotConfigurationRequest) -> Self {
        self.snapshot_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration settings for creating and managing the snapshots that are used for pre-provisioning the AMI for Windows fast launch. The associated <code>ResourceType</code> must be <code>snapshot</code>.</p>
    pub fn set_snapshot_configuration(mut self, input: ::std::option::Option<crate::types::FastLaunchSnapshotConfigurationRequest>) -> Self {
        self.snapshot_configuration = input;
        self
    }
    /// <p>Configuration settings for creating and managing the snapshots that are used for pre-provisioning the AMI for Windows fast launch. The associated <code>ResourceType</code> must be <code>snapshot</code>.</p>
    pub fn get_snapshot_configuration(&self) -> &::std::option::Option<crate::types::FastLaunchSnapshotConfigurationRequest> {
        &self.snapshot_configuration
    }
    /// <p>The launch template to use when launching Windows instances from pre-provisioned snapshots. Launch template parameters can include either the name or ID of the launch template, but not both.</p>
    pub fn launch_template(mut self, input: crate::types::FastLaunchLaunchTemplateSpecificationRequest) -> Self {
        self.launch_template = ::std::option::Option::Some(input);
        self
    }
    /// <p>The launch template to use when launching Windows instances from pre-provisioned snapshots. Launch template parameters can include either the name or ID of the launch template, but not both.</p>
    pub fn set_launch_template(mut self, input: ::std::option::Option<crate::types::FastLaunchLaunchTemplateSpecificationRequest>) -> Self {
        self.launch_template = input;
        self
    }
    /// <p>The launch template to use when launching Windows instances from pre-provisioned snapshots. Launch template parameters can include either the name or ID of the launch template, but not both.</p>
    pub fn get_launch_template(&self) -> &::std::option::Option<crate::types::FastLaunchLaunchTemplateSpecificationRequest> {
        &self.launch_template
    }
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch. Value must be <code>6</code> or greater.</p>
    pub fn max_parallel_launches(mut self, input: i32) -> Self {
        self.max_parallel_launches = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch. Value must be <code>6</code> or greater.</p>
    pub fn set_max_parallel_launches(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_parallel_launches = input;
        self
    }
    /// <p>The maximum number of instances that Amazon EC2 can launch at the same time to create pre-provisioned snapshots for Windows fast launch. Value must be <code>6</code> or greater.</p>
    pub fn get_max_parallel_launches(&self) -> &::std::option::Option<i32> {
        &self.max_parallel_launches
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn dry_run(mut self, input: bool) -> Self {
        self.dry_run = ::std::option::Option::Some(input);
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn set_dry_run(mut self, input: ::std::option::Option<bool>) -> Self {
        self.dry_run = input;
        self
    }
    /// <p>Checks whether you have the required permissions for the action, without actually making the request, and provides an error response. If you have the required permissions, the error response is <code>DryRunOperation</code>. Otherwise, it is <code>UnauthorizedOperation</code>.</p>
    pub fn get_dry_run(&self) -> &::std::option::Option<bool> {
        &self.dry_run
    }
    /// Consumes the builder and constructs a [`EnableFastLaunchInput`](crate::operation::enable_fast_launch::EnableFastLaunchInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::enable_fast_launch::EnableFastLaunchInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::enable_fast_launch::EnableFastLaunchInput {
            image_id: self.image_id,
            resource_type: self.resource_type,
            snapshot_configuration: self.snapshot_configuration,
            launch_template: self.launch_template,
            max_parallel_launches: self.max_parallel_launches,
            dry_run: self.dry_run,
        })
    }
}
