// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a deployment job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeploymentJob {
    /// <p>The Amazon Resource Name (ARN) of the deployment job.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fleet: ::std::option::Option<::std::string::String>,
    /// <p>The status of the deployment job.</p>
    pub status: ::std::option::Option<crate::types::DeploymentStatus>,
    /// <p>The deployment application configuration.</p>
    pub deployment_application_configs: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentApplicationConfig>>,
    /// <p>The deployment configuration.</p>
    pub deployment_config: ::std::option::Option<crate::types::DeploymentConfig>,
    /// <p>A short description of the reason why the deployment job failed.</p>
    pub failure_reason: ::std::option::Option<::std::string::String>,
    /// <p>The deployment job failure code.</p>
    pub failure_code: ::std::option::Option<crate::types::DeploymentJobErrorCode>,
    /// <p>The time, in milliseconds since the epoch, when the deployment job was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl DeploymentJob {
    /// <p>The Amazon Resource Name (ARN) of the deployment job.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fn fleet(&self) -> ::std::option::Option<&str> {
        self.fleet.as_deref()
    }
    /// <p>The status of the deployment job.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DeploymentStatus> {
        self.status.as_ref()
    }
    /// <p>The deployment application configuration.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.deployment_application_configs.is_none()`.
    pub fn deployment_application_configs(&self) -> &[crate::types::DeploymentApplicationConfig] {
        self.deployment_application_configs.as_deref().unwrap_or_default()
    }
    /// <p>The deployment configuration.</p>
    pub fn deployment_config(&self) -> ::std::option::Option<&crate::types::DeploymentConfig> {
        self.deployment_config.as_ref()
    }
    /// <p>A short description of the reason why the deployment job failed.</p>
    pub fn failure_reason(&self) -> ::std::option::Option<&str> {
        self.failure_reason.as_deref()
    }
    /// <p>The deployment job failure code.</p>
    pub fn failure_code(&self) -> ::std::option::Option<&crate::types::DeploymentJobErrorCode> {
        self.failure_code.as_ref()
    }
    /// <p>The time, in milliseconds since the epoch, when the deployment job was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
}
impl DeploymentJob {
    /// Creates a new builder-style object to manufacture [`DeploymentJob`](crate::types::DeploymentJob).
    pub fn builder() -> crate::types::builders::DeploymentJobBuilder {
        crate::types::builders::DeploymentJobBuilder::default()
    }
}

/// A builder for [`DeploymentJob`](crate::types::DeploymentJob).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeploymentJobBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) fleet: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DeploymentStatus>,
    pub(crate) deployment_application_configs: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentApplicationConfig>>,
    pub(crate) deployment_config: ::std::option::Option<crate::types::DeploymentConfig>,
    pub(crate) failure_reason: ::std::option::Option<::std::string::String>,
    pub(crate) failure_code: ::std::option::Option<crate::types::DeploymentJobErrorCode>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl DeploymentJobBuilder {
    /// <p>The Amazon Resource Name (ARN) of the deployment job.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the deployment job.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the deployment job.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fn fleet(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.fleet = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fn set_fleet(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.fleet = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the fleet.</p>
    pub fn get_fleet(&self) -> &::std::option::Option<::std::string::String> {
        &self.fleet
    }
    /// <p>The status of the deployment job.</p>
    pub fn status(mut self, input: crate::types::DeploymentStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the deployment job.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DeploymentStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the deployment job.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DeploymentStatus> {
        &self.status
    }
    /// Appends an item to `deployment_application_configs`.
    ///
    /// To override the contents of this collection use [`set_deployment_application_configs`](Self::set_deployment_application_configs).
    ///
    /// <p>The deployment application configuration.</p>
    pub fn deployment_application_configs(mut self, input: crate::types::DeploymentApplicationConfig) -> Self {
        let mut v = self.deployment_application_configs.unwrap_or_default();
        v.push(input);
        self.deployment_application_configs = ::std::option::Option::Some(v);
        self
    }
    /// <p>The deployment application configuration.</p>
    pub fn set_deployment_application_configs(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::DeploymentApplicationConfig>>,
    ) -> Self {
        self.deployment_application_configs = input;
        self
    }
    /// <p>The deployment application configuration.</p>
    pub fn get_deployment_application_configs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DeploymentApplicationConfig>> {
        &self.deployment_application_configs
    }
    /// <p>The deployment configuration.</p>
    pub fn deployment_config(mut self, input: crate::types::DeploymentConfig) -> Self {
        self.deployment_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The deployment configuration.</p>
    pub fn set_deployment_config(mut self, input: ::std::option::Option<crate::types::DeploymentConfig>) -> Self {
        self.deployment_config = input;
        self
    }
    /// <p>The deployment configuration.</p>
    pub fn get_deployment_config(&self) -> &::std::option::Option<crate::types::DeploymentConfig> {
        &self.deployment_config
    }
    /// <p>A short description of the reason why the deployment job failed.</p>
    pub fn failure_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.failure_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short description of the reason why the deployment job failed.</p>
    pub fn set_failure_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.failure_reason = input;
        self
    }
    /// <p>A short description of the reason why the deployment job failed.</p>
    pub fn get_failure_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.failure_reason
    }
    /// <p>The deployment job failure code.</p>
    pub fn failure_code(mut self, input: crate::types::DeploymentJobErrorCode) -> Self {
        self.failure_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The deployment job failure code.</p>
    pub fn set_failure_code(mut self, input: ::std::option::Option<crate::types::DeploymentJobErrorCode>) -> Self {
        self.failure_code = input;
        self
    }
    /// <p>The deployment job failure code.</p>
    pub fn get_failure_code(&self) -> &::std::option::Option<crate::types::DeploymentJobErrorCode> {
        &self.failure_code
    }
    /// <p>The time, in milliseconds since the epoch, when the deployment job was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the deployment job was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time, in milliseconds since the epoch, when the deployment job was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// Consumes the builder and constructs a [`DeploymentJob`](crate::types::DeploymentJob).
    pub fn build(self) -> crate::types::DeploymentJob {
        crate::types::DeploymentJob {
            arn: self.arn,
            fleet: self.fleet,
            status: self.status,
            deployment_application_configs: self.deployment_application_configs,
            deployment_config: self.deployment_config,
            failure_reason: self.failure_reason,
            failure_code: self.failure_code,
            created_at: self.created_at,
        }
    }
}
