// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>GetDeploymentInstance</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDeploymentInstanceInput {
    /// <p>The unique ID of a deployment.</p>
    pub deployment_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique ID of an instance in the deployment group.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
}
impl GetDeploymentInstanceInput {
    /// <p>The unique ID of a deployment.</p>
    pub fn deployment_id(&self) -> ::std::option::Option<&str> {
        self.deployment_id.as_deref()
    }
    /// <p>The unique ID of an instance in the deployment group.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
}
impl GetDeploymentInstanceInput {
    /// Creates a new builder-style object to manufacture [`GetDeploymentInstanceInput`](crate::operation::get_deployment_instance::GetDeploymentInstanceInput).
    pub fn builder() -> crate::operation::get_deployment_instance::builders::GetDeploymentInstanceInputBuilder {
        crate::operation::get_deployment_instance::builders::GetDeploymentInstanceInputBuilder::default()
    }
}

/// A builder for [`GetDeploymentInstanceInput`](crate::operation::get_deployment_instance::GetDeploymentInstanceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDeploymentInstanceInputBuilder {
    pub(crate) deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
}
impl GetDeploymentInstanceInputBuilder {
    /// <p>The unique ID of a deployment.</p>
    /// This field is required.
    pub fn deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of a deployment.</p>
    pub fn set_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_id = input;
        self
    }
    /// <p>The unique ID of a deployment.</p>
    pub fn get_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_id
    }
    /// <p>The unique ID of an instance in the deployment group.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of an instance in the deployment group.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The unique ID of an instance in the deployment group.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// Consumes the builder and constructs a [`GetDeploymentInstanceInput`](crate::operation::get_deployment_instance::GetDeploymentInstanceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_deployment_instance::GetDeploymentInstanceInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_deployment_instance::GetDeploymentInstanceInput {
            deployment_id: self.deployment_id,
            instance_id: self.instance_id,
        })
    }
}
