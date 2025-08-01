// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An immutable representation of an API that can be called by users. A Deployment must be associated with a Stage for it to be callable over the internet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Deployment {
    /// <p>Specifies whether a deployment was automatically released.</p>
    pub auto_deployed: ::std::option::Option<bool>,
    /// <p>The date and time when the Deployment resource was created.</p>
    pub created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The identifier for the deployment.</p>
    pub deployment_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the deployment: PENDING, FAILED, or SUCCEEDED.</p>
    pub deployment_status: ::std::option::Option<crate::types::DeploymentStatus>,
    /// <p>May contain additional feedback on the status of an API deployment.</p>
    pub deployment_status_message: ::std::option::Option<::std::string::String>,
    /// <p>The description for the deployment.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl Deployment {
    /// <p>Specifies whether a deployment was automatically released.</p>
    pub fn auto_deployed(&self) -> ::std::option::Option<bool> {
        self.auto_deployed
    }
    /// <p>The date and time when the Deployment resource was created.</p>
    pub fn created_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_date.as_ref()
    }
    /// <p>The identifier for the deployment.</p>
    pub fn deployment_id(&self) -> ::std::option::Option<&str> {
        self.deployment_id.as_deref()
    }
    /// <p>The status of the deployment: PENDING, FAILED, or SUCCEEDED.</p>
    pub fn deployment_status(&self) -> ::std::option::Option<&crate::types::DeploymentStatus> {
        self.deployment_status.as_ref()
    }
    /// <p>May contain additional feedback on the status of an API deployment.</p>
    pub fn deployment_status_message(&self) -> ::std::option::Option<&str> {
        self.deployment_status_message.as_deref()
    }
    /// <p>The description for the deployment.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
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
    pub(crate) auto_deployed: ::std::option::Option<bool>,
    pub(crate) created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_status: ::std::option::Option<crate::types::DeploymentStatus>,
    pub(crate) deployment_status_message: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl DeploymentBuilder {
    /// <p>Specifies whether a deployment was automatically released.</p>
    pub fn auto_deployed(mut self, input: bool) -> Self {
        self.auto_deployed = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether a deployment was automatically released.</p>
    pub fn set_auto_deployed(mut self, input: ::std::option::Option<bool>) -> Self {
        self.auto_deployed = input;
        self
    }
    /// <p>Specifies whether a deployment was automatically released.</p>
    pub fn get_auto_deployed(&self) -> &::std::option::Option<bool> {
        &self.auto_deployed
    }
    /// <p>The date and time when the Deployment resource was created.</p>
    pub fn created_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the Deployment resource was created.</p>
    pub fn set_created_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_date = input;
        self
    }
    /// <p>The date and time when the Deployment resource was created.</p>
    pub fn get_created_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_date
    }
    /// <p>The identifier for the deployment.</p>
    pub fn deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the deployment.</p>
    pub fn set_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_id = input;
        self
    }
    /// <p>The identifier for the deployment.</p>
    pub fn get_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_id
    }
    /// <p>The status of the deployment: PENDING, FAILED, or SUCCEEDED.</p>
    pub fn deployment_status(mut self, input: crate::types::DeploymentStatus) -> Self {
        self.deployment_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the deployment: PENDING, FAILED, or SUCCEEDED.</p>
    pub fn set_deployment_status(mut self, input: ::std::option::Option<crate::types::DeploymentStatus>) -> Self {
        self.deployment_status = input;
        self
    }
    /// <p>The status of the deployment: PENDING, FAILED, or SUCCEEDED.</p>
    pub fn get_deployment_status(&self) -> &::std::option::Option<crate::types::DeploymentStatus> {
        &self.deployment_status
    }
    /// <p>May contain additional feedback on the status of an API deployment.</p>
    pub fn deployment_status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>May contain additional feedback on the status of an API deployment.</p>
    pub fn set_deployment_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_status_message = input;
        self
    }
    /// <p>May contain additional feedback on the status of an API deployment.</p>
    pub fn get_deployment_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_status_message
    }
    /// <p>The description for the deployment.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description for the deployment.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description for the deployment.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`Deployment`](crate::types::Deployment).
    pub fn build(self) -> crate::types::Deployment {
        crate::types::Deployment {
            auto_deployed: self.auto_deployed,
            created_date: self.created_date,
            deployment_id: self.deployment_id,
            deployment_status: self.deployment_status,
            deployment_status_message: self.deployment_status_message,
            description: self.description,
        }
    }
}
