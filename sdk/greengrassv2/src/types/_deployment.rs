// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a deployment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Deployment {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> of the target IoT thing or thing group. When creating a subdeployment, the targetARN can only be a thing group.</p>
    pub target_arn: ::std::option::Option<::std::string::String>,
    /// <p>The revision number of the deployment.</p>
    pub revision_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the deployment.</p>
    pub deployment_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the deployment.</p>
    pub deployment_name: ::std::option::Option<::std::string::String>,
    /// <p>The time at which the deployment was created, expressed in ISO 8601 format.</p>
    pub creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the deployment.</p>
    pub deployment_status: ::std::option::Option<crate::types::DeploymentStatus>,
    /// <p>Whether or not the deployment is the latest revision for its target.</p>
    pub is_latest_for_target: bool,
    /// <p>The parent deployment's target <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> within a subdeployment.</p>
    pub parent_target_arn: ::std::option::Option<::std::string::String>,
}
impl Deployment {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> of the target IoT thing or thing group. When creating a subdeployment, the targetARN can only be a thing group.</p>
    pub fn target_arn(&self) -> ::std::option::Option<&str> {
        self.target_arn.as_deref()
    }
    /// <p>The revision number of the deployment.</p>
    pub fn revision_id(&self) -> ::std::option::Option<&str> {
        self.revision_id.as_deref()
    }
    /// <p>The ID of the deployment.</p>
    pub fn deployment_id(&self) -> ::std::option::Option<&str> {
        self.deployment_id.as_deref()
    }
    /// <p>The name of the deployment.</p>
    pub fn deployment_name(&self) -> ::std::option::Option<&str> {
        self.deployment_name.as_deref()
    }
    /// <p>The time at which the deployment was created, expressed in ISO 8601 format.</p>
    pub fn creation_timestamp(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_timestamp.as_ref()
    }
    /// <p>The status of the deployment.</p>
    pub fn deployment_status(&self) -> ::std::option::Option<&crate::types::DeploymentStatus> {
        self.deployment_status.as_ref()
    }
    /// <p>Whether or not the deployment is the latest revision for its target.</p>
    pub fn is_latest_for_target(&self) -> bool {
        self.is_latest_for_target
    }
    /// <p>The parent deployment's target <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> within a subdeployment.</p>
    pub fn parent_target_arn(&self) -> ::std::option::Option<&str> {
        self.parent_target_arn.as_deref()
    }
}
impl Deployment {
    /// Creates a new builder-style object to manufacture [`Deployment`](crate::types::Deployment).
    pub fn builder() -> crate::types::builders::DeploymentBuilder {
        crate::types::builders::DeploymentBuilder::default()
    }
}

/// A builder for [`Deployment`](crate::types::Deployment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeploymentBuilder {
    pub(crate) target_arn: ::std::option::Option<::std::string::String>,
    pub(crate) revision_id: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_name: ::std::option::Option<::std::string::String>,
    pub(crate) creation_timestamp: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) deployment_status: ::std::option::Option<crate::types::DeploymentStatus>,
    pub(crate) is_latest_for_target: ::std::option::Option<bool>,
    pub(crate) parent_target_arn: ::std::option::Option<::std::string::String>,
}
impl DeploymentBuilder {
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> of the target IoT thing or thing group. When creating a subdeployment, the targetARN can only be a thing group.</p>
    pub fn target_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> of the target IoT thing or thing group. When creating a subdeployment, the targetARN can only be a thing group.</p>
    pub fn set_target_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_arn = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> of the target IoT thing or thing group. When creating a subdeployment, the targetARN can only be a thing group.</p>
    pub fn get_target_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_arn
    }
    /// <p>The revision number of the deployment.</p>
    pub fn revision_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.revision_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The revision number of the deployment.</p>
    pub fn set_revision_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.revision_id = input;
        self
    }
    /// <p>The revision number of the deployment.</p>
    pub fn get_revision_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.revision_id
    }
    /// <p>The ID of the deployment.</p>
    pub fn deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the deployment.</p>
    pub fn set_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_id = input;
        self
    }
    /// <p>The ID of the deployment.</p>
    pub fn get_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_id
    }
    /// <p>The name of the deployment.</p>
    pub fn deployment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the deployment.</p>
    pub fn set_deployment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_name = input;
        self
    }
    /// <p>The name of the deployment.</p>
    pub fn get_deployment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_name
    }
    /// <p>The time at which the deployment was created, expressed in ISO 8601 format.</p>
    pub fn creation_timestamp(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_timestamp = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time at which the deployment was created, expressed in ISO 8601 format.</p>
    pub fn set_creation_timestamp(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_timestamp = input;
        self
    }
    /// <p>The time at which the deployment was created, expressed in ISO 8601 format.</p>
    pub fn get_creation_timestamp(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_timestamp
    }
    /// <p>The status of the deployment.</p>
    pub fn deployment_status(mut self, input: crate::types::DeploymentStatus) -> Self {
        self.deployment_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the deployment.</p>
    pub fn set_deployment_status(mut self, input: ::std::option::Option<crate::types::DeploymentStatus>) -> Self {
        self.deployment_status = input;
        self
    }
    /// <p>The status of the deployment.</p>
    pub fn get_deployment_status(&self) -> &::std::option::Option<crate::types::DeploymentStatus> {
        &self.deployment_status
    }
    /// <p>Whether or not the deployment is the latest revision for its target.</p>
    pub fn is_latest_for_target(mut self, input: bool) -> Self {
        self.is_latest_for_target = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether or not the deployment is the latest revision for its target.</p>
    pub fn set_is_latest_for_target(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_latest_for_target = input;
        self
    }
    /// <p>Whether or not the deployment is the latest revision for its target.</p>
    pub fn get_is_latest_for_target(&self) -> &::std::option::Option<bool> {
        &self.is_latest_for_target
    }
    /// <p>The parent deployment's target <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> within a subdeployment.</p>
    pub fn parent_target_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_target_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The parent deployment's target <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> within a subdeployment.</p>
    pub fn set_parent_target_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_target_arn = input;
        self
    }
    /// <p>The parent deployment's target <a href="https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html">ARN</a> within a subdeployment.</p>
    pub fn get_parent_target_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_target_arn
    }
    /// Consumes the builder and constructs a [`Deployment`](crate::types::Deployment).
    pub fn build(self) -> crate::types::Deployment {
        crate::types::Deployment {
            target_arn: self.target_arn,
            revision_id: self.revision_id,
            deployment_id: self.deployment_id,
            deployment_name: self.deployment_name,
            creation_timestamp: self.creation_timestamp,
            deployment_status: self.deployment_status,
            is_latest_for_target: self.is_latest_for_target.unwrap_or_default(),
            parent_target_arn: self.parent_target_arn,
        }
    }
}
