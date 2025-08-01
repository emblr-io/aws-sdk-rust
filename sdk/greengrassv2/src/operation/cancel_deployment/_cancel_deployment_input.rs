// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelDeploymentInput {
    /// <p>The ID of the deployment.</p>
    pub deployment_id: ::std::option::Option<::std::string::String>,
}
impl CancelDeploymentInput {
    /// <p>The ID of the deployment.</p>
    pub fn deployment_id(&self) -> ::std::option::Option<&str> {
        self.deployment_id.as_deref()
    }
}
impl CancelDeploymentInput {
    /// Creates a new builder-style object to manufacture [`CancelDeploymentInput`](crate::operation::cancel_deployment::CancelDeploymentInput).
    pub fn builder() -> crate::operation::cancel_deployment::builders::CancelDeploymentInputBuilder {
        crate::operation::cancel_deployment::builders::CancelDeploymentInputBuilder::default()
    }
}

/// A builder for [`CancelDeploymentInput`](crate::operation::cancel_deployment::CancelDeploymentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelDeploymentInputBuilder {
    pub(crate) deployment_id: ::std::option::Option<::std::string::String>,
}
impl CancelDeploymentInputBuilder {
    /// <p>The ID of the deployment.</p>
    /// This field is required.
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
    /// Consumes the builder and constructs a [`CancelDeploymentInput`](crate::operation::cancel_deployment::CancelDeploymentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::cancel_deployment::CancelDeploymentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::cancel_deployment::CancelDeploymentInput {
            deployment_id: self.deployment_id,
        })
    }
}
