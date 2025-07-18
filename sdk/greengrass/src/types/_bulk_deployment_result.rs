// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Information about an individual group deployment in a bulk deployment operation.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BulkDeploymentResult {
    /// The time, in ISO format, when the deployment was created.
    pub created_at: ::std::option::Option<::std::string::String>,
    /// The ARN of the group deployment.
    pub deployment_arn: ::std::option::Option<::std::string::String>,
    /// The ID of the group deployment.
    pub deployment_id: ::std::option::Option<::std::string::String>,
    /// The current status of the group deployment: ''InProgress'', ''Building'', ''Success'', or ''Failure''.
    pub deployment_status: ::std::option::Option<::std::string::String>,
    /// The type of the deployment.
    pub deployment_type: ::std::option::Option<crate::types::DeploymentType>,
    /// Details about the error.
    pub error_details: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetail>>,
    /// The error message for a failed deployment
    pub error_message: ::std::option::Option<::std::string::String>,
    /// The ARN of the Greengrass group.
    pub group_arn: ::std::option::Option<::std::string::String>,
}
impl BulkDeploymentResult {
    /// The time, in ISO format, when the deployment was created.
    pub fn created_at(&self) -> ::std::option::Option<&str> {
        self.created_at.as_deref()
    }
    /// The ARN of the group deployment.
    pub fn deployment_arn(&self) -> ::std::option::Option<&str> {
        self.deployment_arn.as_deref()
    }
    /// The ID of the group deployment.
    pub fn deployment_id(&self) -> ::std::option::Option<&str> {
        self.deployment_id.as_deref()
    }
    /// The current status of the group deployment: ''InProgress'', ''Building'', ''Success'', or ''Failure''.
    pub fn deployment_status(&self) -> ::std::option::Option<&str> {
        self.deployment_status.as_deref()
    }
    /// The type of the deployment.
    pub fn deployment_type(&self) -> ::std::option::Option<&crate::types::DeploymentType> {
        self.deployment_type.as_ref()
    }
    /// Details about the error.
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.error_details.is_none()`.
    pub fn error_details(&self) -> &[crate::types::ErrorDetail] {
        self.error_details.as_deref().unwrap_or_default()
    }
    /// The error message for a failed deployment
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// The ARN of the Greengrass group.
    pub fn group_arn(&self) -> ::std::option::Option<&str> {
        self.group_arn.as_deref()
    }
}
impl BulkDeploymentResult {
    /// Creates a new builder-style object to manufacture [`BulkDeploymentResult`](crate::types::BulkDeploymentResult).
    pub fn builder() -> crate::types::builders::BulkDeploymentResultBuilder {
        crate::types::builders::BulkDeploymentResultBuilder::default()
    }
}

/// A builder for [`BulkDeploymentResult`](crate::types::BulkDeploymentResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BulkDeploymentResultBuilder {
    pub(crate) created_at: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_arn: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_status: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_type: ::std::option::Option<crate::types::DeploymentType>,
    pub(crate) error_details: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetail>>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) group_arn: ::std::option::Option<::std::string::String>,
}
impl BulkDeploymentResultBuilder {
    /// The time, in ISO format, when the deployment was created.
    pub fn created_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_at = ::std::option::Option::Some(input.into());
        self
    }
    /// The time, in ISO format, when the deployment was created.
    pub fn set_created_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_at = input;
        self
    }
    /// The time, in ISO format, when the deployment was created.
    pub fn get_created_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_at
    }
    /// The ARN of the group deployment.
    pub fn deployment_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The ARN of the group deployment.
    pub fn set_deployment_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_arn = input;
        self
    }
    /// The ARN of the group deployment.
    pub fn get_deployment_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_arn
    }
    /// The ID of the group deployment.
    pub fn deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the group deployment.
    pub fn set_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_id = input;
        self
    }
    /// The ID of the group deployment.
    pub fn get_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_id
    }
    /// The current status of the group deployment: ''InProgress'', ''Building'', ''Success'', or ''Failure''.
    pub fn deployment_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_status = ::std::option::Option::Some(input.into());
        self
    }
    /// The current status of the group deployment: ''InProgress'', ''Building'', ''Success'', or ''Failure''.
    pub fn set_deployment_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_status = input;
        self
    }
    /// The current status of the group deployment: ''InProgress'', ''Building'', ''Success'', or ''Failure''.
    pub fn get_deployment_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_status
    }
    /// The type of the deployment.
    pub fn deployment_type(mut self, input: crate::types::DeploymentType) -> Self {
        self.deployment_type = ::std::option::Option::Some(input);
        self
    }
    /// The type of the deployment.
    pub fn set_deployment_type(mut self, input: ::std::option::Option<crate::types::DeploymentType>) -> Self {
        self.deployment_type = input;
        self
    }
    /// The type of the deployment.
    pub fn get_deployment_type(&self) -> &::std::option::Option<crate::types::DeploymentType> {
        &self.deployment_type
    }
    /// Appends an item to `error_details`.
    ///
    /// To override the contents of this collection use [`set_error_details`](Self::set_error_details).
    ///
    /// Details about the error.
    pub fn error_details(mut self, input: crate::types::ErrorDetail) -> Self {
        let mut v = self.error_details.unwrap_or_default();
        v.push(input);
        self.error_details = ::std::option::Option::Some(v);
        self
    }
    /// Details about the error.
    pub fn set_error_details(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ErrorDetail>>) -> Self {
        self.error_details = input;
        self
    }
    /// Details about the error.
    pub fn get_error_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ErrorDetail>> {
        &self.error_details
    }
    /// The error message for a failed deployment
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// The error message for a failed deployment
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// The error message for a failed deployment
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// The ARN of the Greengrass group.
    pub fn group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The ARN of the Greengrass group.
    pub fn set_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_arn = input;
        self
    }
    /// The ARN of the Greengrass group.
    pub fn get_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_arn
    }
    /// Consumes the builder and constructs a [`BulkDeploymentResult`](crate::types::BulkDeploymentResult).
    pub fn build(self) -> crate::types::BulkDeploymentResult {
        crate::types::BulkDeploymentResult {
            created_at: self.created_at,
            deployment_arn: self.deployment_arn,
            deployment_id: self.deployment_id,
            deployment_status: self.deployment_status,
            deployment_type: self.deployment_type,
            error_details: self.error_details,
            error_message: self.error_message,
            group_arn: self.group_arn,
        }
    }
}
