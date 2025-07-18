// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>GetDeploymentGroup</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDeploymentGroupOutput {
    /// <p>Information about the deployment group.</p>
    pub deployment_group_info: ::std::option::Option<crate::types::DeploymentGroupInfo>,
    _request_id: Option<String>,
}
impl GetDeploymentGroupOutput {
    /// <p>Information about the deployment group.</p>
    pub fn deployment_group_info(&self) -> ::std::option::Option<&crate::types::DeploymentGroupInfo> {
        self.deployment_group_info.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDeploymentGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDeploymentGroupOutput {
    /// Creates a new builder-style object to manufacture [`GetDeploymentGroupOutput`](crate::operation::get_deployment_group::GetDeploymentGroupOutput).
    pub fn builder() -> crate::operation::get_deployment_group::builders::GetDeploymentGroupOutputBuilder {
        crate::operation::get_deployment_group::builders::GetDeploymentGroupOutputBuilder::default()
    }
}

/// A builder for [`GetDeploymentGroupOutput`](crate::operation::get_deployment_group::GetDeploymentGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDeploymentGroupOutputBuilder {
    pub(crate) deployment_group_info: ::std::option::Option<crate::types::DeploymentGroupInfo>,
    _request_id: Option<String>,
}
impl GetDeploymentGroupOutputBuilder {
    /// <p>Information about the deployment group.</p>
    pub fn deployment_group_info(mut self, input: crate::types::DeploymentGroupInfo) -> Self {
        self.deployment_group_info = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the deployment group.</p>
    pub fn set_deployment_group_info(mut self, input: ::std::option::Option<crate::types::DeploymentGroupInfo>) -> Self {
        self.deployment_group_info = input;
        self
    }
    /// <p>Information about the deployment group.</p>
    pub fn get_deployment_group_info(&self) -> &::std::option::Option<crate::types::DeploymentGroupInfo> {
        &self.deployment_group_info
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDeploymentGroupOutput`](crate::operation::get_deployment_group::GetDeploymentGroupOutput).
    pub fn build(self) -> crate::operation::get_deployment_group::GetDeploymentGroupOutput {
        crate::operation::get_deployment_group::GetDeploymentGroupOutput {
            deployment_group_info: self.deployment_group_info,
            _request_id: self._request_id,
        }
    }
}
