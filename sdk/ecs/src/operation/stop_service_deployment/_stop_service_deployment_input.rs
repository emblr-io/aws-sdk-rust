// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopServiceDeploymentInput {
    /// <p>The ARN of the service deployment that you want to stop.</p>
    pub service_deployment_arn: ::std::option::Option<::std::string::String>,
    /// <p>How you want Amazon ECS to stop the service.</p>
    /// <p>The valid values are <code>ROLLBACK</code>.</p>
    pub stop_type: ::std::option::Option<crate::types::StopServiceDeploymentStopType>,
}
impl StopServiceDeploymentInput {
    /// <p>The ARN of the service deployment that you want to stop.</p>
    pub fn service_deployment_arn(&self) -> ::std::option::Option<&str> {
        self.service_deployment_arn.as_deref()
    }
    /// <p>How you want Amazon ECS to stop the service.</p>
    /// <p>The valid values are <code>ROLLBACK</code>.</p>
    pub fn stop_type(&self) -> ::std::option::Option<&crate::types::StopServiceDeploymentStopType> {
        self.stop_type.as_ref()
    }
}
impl StopServiceDeploymentInput {
    /// Creates a new builder-style object to manufacture [`StopServiceDeploymentInput`](crate::operation::stop_service_deployment::StopServiceDeploymentInput).
    pub fn builder() -> crate::operation::stop_service_deployment::builders::StopServiceDeploymentInputBuilder {
        crate::operation::stop_service_deployment::builders::StopServiceDeploymentInputBuilder::default()
    }
}

/// A builder for [`StopServiceDeploymentInput`](crate::operation::stop_service_deployment::StopServiceDeploymentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopServiceDeploymentInputBuilder {
    pub(crate) service_deployment_arn: ::std::option::Option<::std::string::String>,
    pub(crate) stop_type: ::std::option::Option<crate::types::StopServiceDeploymentStopType>,
}
impl StopServiceDeploymentInputBuilder {
    /// <p>The ARN of the service deployment that you want to stop.</p>
    /// This field is required.
    pub fn service_deployment_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_deployment_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the service deployment that you want to stop.</p>
    pub fn set_service_deployment_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_deployment_arn = input;
        self
    }
    /// <p>The ARN of the service deployment that you want to stop.</p>
    pub fn get_service_deployment_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_deployment_arn
    }
    /// <p>How you want Amazon ECS to stop the service.</p>
    /// <p>The valid values are <code>ROLLBACK</code>.</p>
    pub fn stop_type(mut self, input: crate::types::StopServiceDeploymentStopType) -> Self {
        self.stop_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>How you want Amazon ECS to stop the service.</p>
    /// <p>The valid values are <code>ROLLBACK</code>.</p>
    pub fn set_stop_type(mut self, input: ::std::option::Option<crate::types::StopServiceDeploymentStopType>) -> Self {
        self.stop_type = input;
        self
    }
    /// <p>How you want Amazon ECS to stop the service.</p>
    /// <p>The valid values are <code>ROLLBACK</code>.</p>
    pub fn get_stop_type(&self) -> &::std::option::Option<crate::types::StopServiceDeploymentStopType> {
        &self.stop_type
    }
    /// Consumes the builder and constructs a [`StopServiceDeploymentInput`](crate::operation::stop_service_deployment::StopServiceDeploymentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::stop_service_deployment::StopServiceDeploymentInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::stop_service_deployment::StopServiceDeploymentInput {
            service_deployment_arn: self.service_deployment_arn,
            stop_type: self.stop_type,
        })
    }
}
