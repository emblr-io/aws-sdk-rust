// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>GetDeploymentConfig</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDeploymentConfigOutput {
    /// <p>Information about the deployment configuration.</p>
    pub deployment_config_info: ::std::option::Option<crate::types::DeploymentConfigInfo>,
    _request_id: Option<String>,
}
impl GetDeploymentConfigOutput {
    /// <p>Information about the deployment configuration.</p>
    pub fn deployment_config_info(&self) -> ::std::option::Option<&crate::types::DeploymentConfigInfo> {
        self.deployment_config_info.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDeploymentConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDeploymentConfigOutput {
    /// Creates a new builder-style object to manufacture [`GetDeploymentConfigOutput`](crate::operation::get_deployment_config::GetDeploymentConfigOutput).
    pub fn builder() -> crate::operation::get_deployment_config::builders::GetDeploymentConfigOutputBuilder {
        crate::operation::get_deployment_config::builders::GetDeploymentConfigOutputBuilder::default()
    }
}

/// A builder for [`GetDeploymentConfigOutput`](crate::operation::get_deployment_config::GetDeploymentConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDeploymentConfigOutputBuilder {
    pub(crate) deployment_config_info: ::std::option::Option<crate::types::DeploymentConfigInfo>,
    _request_id: Option<String>,
}
impl GetDeploymentConfigOutputBuilder {
    /// <p>Information about the deployment configuration.</p>
    pub fn deployment_config_info(mut self, input: crate::types::DeploymentConfigInfo) -> Self {
        self.deployment_config_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the deployment configuration.</p>
    pub fn set_deployment_config_info(mut self, input: ::std::option::Option<crate::types::DeploymentConfigInfo>) -> Self {
        self.deployment_config_info = input;
        self
    }
    /// <p>Information about the deployment configuration.</p>
    pub fn get_deployment_config_info(&self) -> &::std::option::Option<crate::types::DeploymentConfigInfo> {
        &self.deployment_config_info
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDeploymentConfigOutput`](crate::operation::get_deployment_config::GetDeploymentConfigOutput).
    pub fn build(self) -> crate::operation::get_deployment_config::GetDeploymentConfigOutput {
        crate::operation::get_deployment_config::GetDeploymentConfigOutput {
            deployment_config_info: self.deployment_config_info,
            _request_id: self._request_id,
        }
    }
}
