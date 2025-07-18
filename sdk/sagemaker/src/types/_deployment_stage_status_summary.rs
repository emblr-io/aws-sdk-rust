// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information summarizing the deployment stage results.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeploymentStageStatusSummary {
    /// <p>The name of the stage.</p>
    pub stage_name: ::std::option::Option<::std::string::String>,
    /// <p>Configuration of the devices in the stage.</p>
    pub device_selection_config: ::std::option::Option<crate::types::DeviceSelectionConfig>,
    /// <p>Configuration of the deployment details.</p>
    pub deployment_config: ::std::option::Option<crate::types::EdgeDeploymentConfig>,
    /// <p>General status of the current state.</p>
    pub deployment_status: ::std::option::Option<crate::types::EdgeDeploymentStatus>,
}
impl DeploymentStageStatusSummary {
    /// <p>The name of the stage.</p>
    pub fn stage_name(&self) -> ::std::option::Option<&str> {
        self.stage_name.as_deref()
    }
    /// <p>Configuration of the devices in the stage.</p>
    pub fn device_selection_config(&self) -> ::std::option::Option<&crate::types::DeviceSelectionConfig> {
        self.device_selection_config.as_ref()
    }
    /// <p>Configuration of the deployment details.</p>
    pub fn deployment_config(&self) -> ::std::option::Option<&crate::types::EdgeDeploymentConfig> {
        self.deployment_config.as_ref()
    }
    /// <p>General status of the current state.</p>
    pub fn deployment_status(&self) -> ::std::option::Option<&crate::types::EdgeDeploymentStatus> {
        self.deployment_status.as_ref()
    }
}
impl DeploymentStageStatusSummary {
    /// Creates a new builder-style object to manufacture [`DeploymentStageStatusSummary`](crate::types::DeploymentStageStatusSummary).
    pub fn builder() -> crate::types::builders::DeploymentStageStatusSummaryBuilder {
        crate::types::builders::DeploymentStageStatusSummaryBuilder::default()
    }
}

/// A builder for [`DeploymentStageStatusSummary`](crate::types::DeploymentStageStatusSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeploymentStageStatusSummaryBuilder {
    pub(crate) stage_name: ::std::option::Option<::std::string::String>,
    pub(crate) device_selection_config: ::std::option::Option<crate::types::DeviceSelectionConfig>,
    pub(crate) deployment_config: ::std::option::Option<crate::types::EdgeDeploymentConfig>,
    pub(crate) deployment_status: ::std::option::Option<crate::types::EdgeDeploymentStatus>,
}
impl DeploymentStageStatusSummaryBuilder {
    /// <p>The name of the stage.</p>
    /// This field is required.
    pub fn stage_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stage_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stage.</p>
    pub fn set_stage_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stage_name = input;
        self
    }
    /// <p>The name of the stage.</p>
    pub fn get_stage_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stage_name
    }
    /// <p>Configuration of the devices in the stage.</p>
    /// This field is required.
    pub fn device_selection_config(mut self, input: crate::types::DeviceSelectionConfig) -> Self {
        self.device_selection_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration of the devices in the stage.</p>
    pub fn set_device_selection_config(mut self, input: ::std::option::Option<crate::types::DeviceSelectionConfig>) -> Self {
        self.device_selection_config = input;
        self
    }
    /// <p>Configuration of the devices in the stage.</p>
    pub fn get_device_selection_config(&self) -> &::std::option::Option<crate::types::DeviceSelectionConfig> {
        &self.device_selection_config
    }
    /// <p>Configuration of the deployment details.</p>
    /// This field is required.
    pub fn deployment_config(mut self, input: crate::types::EdgeDeploymentConfig) -> Self {
        self.deployment_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration of the deployment details.</p>
    pub fn set_deployment_config(mut self, input: ::std::option::Option<crate::types::EdgeDeploymentConfig>) -> Self {
        self.deployment_config = input;
        self
    }
    /// <p>Configuration of the deployment details.</p>
    pub fn get_deployment_config(&self) -> &::std::option::Option<crate::types::EdgeDeploymentConfig> {
        &self.deployment_config
    }
    /// <p>General status of the current state.</p>
    /// This field is required.
    pub fn deployment_status(mut self, input: crate::types::EdgeDeploymentStatus) -> Self {
        self.deployment_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>General status of the current state.</p>
    pub fn set_deployment_status(mut self, input: ::std::option::Option<crate::types::EdgeDeploymentStatus>) -> Self {
        self.deployment_status = input;
        self
    }
    /// <p>General status of the current state.</p>
    pub fn get_deployment_status(&self) -> &::std::option::Option<crate::types::EdgeDeploymentStatus> {
        &self.deployment_status
    }
    /// Consumes the builder and constructs a [`DeploymentStageStatusSummary`](crate::types::DeploymentStageStatusSummary).
    pub fn build(self) -> crate::types::DeploymentStageStatusSummary {
        crate::types::DeploymentStageStatusSummary {
            stage_name: self.stage_name,
            device_selection_config: self.device_selection_config,
            deployment_config: self.deployment_config,
            deployment_status: self.deployment_status,
        }
    }
}
