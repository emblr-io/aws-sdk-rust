// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>GetDeployment</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDeploymentOutput {
    /// <p>Information about the deployment.</p>
    pub deployment_info: ::std::option::Option<crate::types::DeploymentInfo>,
    _request_id: Option<String>,
}
impl GetDeploymentOutput {
    /// <p>Information about the deployment.</p>
    pub fn deployment_info(&self) -> ::std::option::Option<&crate::types::DeploymentInfo> {
        self.deployment_info.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDeploymentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDeploymentOutput {
    /// Creates a new builder-style object to manufacture [`GetDeploymentOutput`](crate::operation::get_deployment::GetDeploymentOutput).
    pub fn builder() -> crate::operation::get_deployment::builders::GetDeploymentOutputBuilder {
        crate::operation::get_deployment::builders::GetDeploymentOutputBuilder::default()
    }
}

/// A builder for [`GetDeploymentOutput`](crate::operation::get_deployment::GetDeploymentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDeploymentOutputBuilder {
    pub(crate) deployment_info: ::std::option::Option<crate::types::DeploymentInfo>,
    _request_id: Option<String>,
}
impl GetDeploymentOutputBuilder {
    /// <p>Information about the deployment.</p>
    pub fn deployment_info(mut self, input: crate::types::DeploymentInfo) -> Self {
        self.deployment_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the deployment.</p>
    pub fn set_deployment_info(mut self, input: ::std::option::Option<crate::types::DeploymentInfo>) -> Self {
        self.deployment_info = input;
        self
    }
    /// <p>Information about the deployment.</p>
    pub fn get_deployment_info(&self) -> &::std::option::Option<crate::types::DeploymentInfo> {
        &self.deployment_info
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDeploymentOutput`](crate::operation::get_deployment::GetDeploymentOutput).
    pub fn build(self) -> crate::operation::get_deployment::GetDeploymentOutput {
        crate::operation::get_deployment::GetDeploymentOutput {
            deployment_info: self.deployment_info,
            _request_id: self._request_id,
        }
    }
}
