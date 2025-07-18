// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopServiceDeploymentOutput {
    /// <p>The ARN of the stopped service deployment.</p>
    pub service_deployment_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StopServiceDeploymentOutput {
    /// <p>The ARN of the stopped service deployment.</p>
    pub fn service_deployment_arn(&self) -> ::std::option::Option<&str> {
        self.service_deployment_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StopServiceDeploymentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopServiceDeploymentOutput {
    /// Creates a new builder-style object to manufacture [`StopServiceDeploymentOutput`](crate::operation::stop_service_deployment::StopServiceDeploymentOutput).
    pub fn builder() -> crate::operation::stop_service_deployment::builders::StopServiceDeploymentOutputBuilder {
        crate::operation::stop_service_deployment::builders::StopServiceDeploymentOutputBuilder::default()
    }
}

/// A builder for [`StopServiceDeploymentOutput`](crate::operation::stop_service_deployment::StopServiceDeploymentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopServiceDeploymentOutputBuilder {
    pub(crate) service_deployment_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StopServiceDeploymentOutputBuilder {
    /// <p>The ARN of the stopped service deployment.</p>
    pub fn service_deployment_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_deployment_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the stopped service deployment.</p>
    pub fn set_service_deployment_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_deployment_arn = input;
        self
    }
    /// <p>The ARN of the stopped service deployment.</p>
    pub fn get_service_deployment_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_deployment_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopServiceDeploymentOutput`](crate::operation::stop_service_deployment::StopServiceDeploymentOutput).
    pub fn build(self) -> crate::operation::stop_service_deployment::StopServiceDeploymentOutput {
        crate::operation::stop_service_deployment::StopServiceDeploymentOutput {
            service_deployment_arn: self.service_deployment_arn,
            _request_id: self._request_id,
        }
    }
}
