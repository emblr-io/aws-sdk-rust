// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelServiceInstanceDeploymentInput {
    /// <p>The name of the service instance with the deployment to cancel.</p>
    pub service_instance_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the service with the service instance deployment to cancel.</p>
    pub service_name: ::std::option::Option<::std::string::String>,
}
impl CancelServiceInstanceDeploymentInput {
    /// <p>The name of the service instance with the deployment to cancel.</p>
    pub fn service_instance_name(&self) -> ::std::option::Option<&str> {
        self.service_instance_name.as_deref()
    }
    /// <p>The name of the service with the service instance deployment to cancel.</p>
    pub fn service_name(&self) -> ::std::option::Option<&str> {
        self.service_name.as_deref()
    }
}
impl CancelServiceInstanceDeploymentInput {
    /// Creates a new builder-style object to manufacture [`CancelServiceInstanceDeploymentInput`](crate::operation::cancel_service_instance_deployment::CancelServiceInstanceDeploymentInput).
    pub fn builder() -> crate::operation::cancel_service_instance_deployment::builders::CancelServiceInstanceDeploymentInputBuilder {
        crate::operation::cancel_service_instance_deployment::builders::CancelServiceInstanceDeploymentInputBuilder::default()
    }
}

/// A builder for [`CancelServiceInstanceDeploymentInput`](crate::operation::cancel_service_instance_deployment::CancelServiceInstanceDeploymentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelServiceInstanceDeploymentInputBuilder {
    pub(crate) service_instance_name: ::std::option::Option<::std::string::String>,
    pub(crate) service_name: ::std::option::Option<::std::string::String>,
}
impl CancelServiceInstanceDeploymentInputBuilder {
    /// <p>The name of the service instance with the deployment to cancel.</p>
    /// This field is required.
    pub fn service_instance_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_instance_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service instance with the deployment to cancel.</p>
    pub fn set_service_instance_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_instance_name = input;
        self
    }
    /// <p>The name of the service instance with the deployment to cancel.</p>
    pub fn get_service_instance_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_instance_name
    }
    /// <p>The name of the service with the service instance deployment to cancel.</p>
    /// This field is required.
    pub fn service_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the service with the service instance deployment to cancel.</p>
    pub fn set_service_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_name = input;
        self
    }
    /// <p>The name of the service with the service instance deployment to cancel.</p>
    pub fn get_service_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_name
    }
    /// Consumes the builder and constructs a [`CancelServiceInstanceDeploymentInput`](crate::operation::cancel_service_instance_deployment::CancelServiceInstanceDeploymentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::cancel_service_instance_deployment::CancelServiceInstanceDeploymentInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::cancel_service_instance_deployment::CancelServiceInstanceDeploymentInput {
                service_instance_name: self.service_instance_name,
                service_name: self.service_name,
            },
        )
    }
}
