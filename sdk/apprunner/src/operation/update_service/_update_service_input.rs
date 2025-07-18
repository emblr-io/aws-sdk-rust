// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateServiceInput {
    /// <p>The Amazon Resource Name (ARN) of the App Runner service that you want to update.</p>
    pub service_arn: ::std::option::Option<::std::string::String>,
    /// <p>The source configuration to apply to the App Runner service.</p>
    /// <p>You can change the configuration of the code or image repository that the service uses. However, you can't switch from code to image or the other way around. This means that you must provide the same structure member of <code>SourceConfiguration</code> that you originally included when you created the service. Specifically, you can include either <code>CodeRepository</code> or <code>ImageRepository</code>. To update the source configuration, set the values to members of the structure that you include.</p>
    pub source_configuration: ::std::option::Option<crate::types::SourceConfiguration>,
    /// <p>The runtime configuration to apply to instances (scaling units) of your service.</p>
    pub instance_configuration: ::std::option::Option<crate::types::InstanceConfiguration>,
    /// <p>The Amazon Resource Name (ARN) of an App Runner automatic scaling configuration resource that you want to associate with the App Runner service.</p>
    pub auto_scaling_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The settings for the health check that App Runner performs to monitor the health of the App Runner service.</p>
    pub health_check_configuration: ::std::option::Option<crate::types::HealthCheckConfiguration>,
    /// <p>Configuration settings related to network traffic of the web application that the App Runner service runs.</p>
    pub network_configuration: ::std::option::Option<crate::types::NetworkConfiguration>,
    /// <p>The observability configuration of your service.</p>
    pub observability_configuration: ::std::option::Option<crate::types::ServiceObservabilityConfiguration>,
}
impl UpdateServiceInput {
    /// <p>The Amazon Resource Name (ARN) of the App Runner service that you want to update.</p>
    pub fn service_arn(&self) -> ::std::option::Option<&str> {
        self.service_arn.as_deref()
    }
    /// <p>The source configuration to apply to the App Runner service.</p>
    /// <p>You can change the configuration of the code or image repository that the service uses. However, you can't switch from code to image or the other way around. This means that you must provide the same structure member of <code>SourceConfiguration</code> that you originally included when you created the service. Specifically, you can include either <code>CodeRepository</code> or <code>ImageRepository</code>. To update the source configuration, set the values to members of the structure that you include.</p>
    pub fn source_configuration(&self) -> ::std::option::Option<&crate::types::SourceConfiguration> {
        self.source_configuration.as_ref()
    }
    /// <p>The runtime configuration to apply to instances (scaling units) of your service.</p>
    pub fn instance_configuration(&self) -> ::std::option::Option<&crate::types::InstanceConfiguration> {
        self.instance_configuration.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of an App Runner automatic scaling configuration resource that you want to associate with the App Runner service.</p>
    pub fn auto_scaling_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_configuration_arn.as_deref()
    }
    /// <p>The settings for the health check that App Runner performs to monitor the health of the App Runner service.</p>
    pub fn health_check_configuration(&self) -> ::std::option::Option<&crate::types::HealthCheckConfiguration> {
        self.health_check_configuration.as_ref()
    }
    /// <p>Configuration settings related to network traffic of the web application that the App Runner service runs.</p>
    pub fn network_configuration(&self) -> ::std::option::Option<&crate::types::NetworkConfiguration> {
        self.network_configuration.as_ref()
    }
    /// <p>The observability configuration of your service.</p>
    pub fn observability_configuration(&self) -> ::std::option::Option<&crate::types::ServiceObservabilityConfiguration> {
        self.observability_configuration.as_ref()
    }
}
impl UpdateServiceInput {
    /// Creates a new builder-style object to manufacture [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
    pub fn builder() -> crate::operation::update_service::builders::UpdateServiceInputBuilder {
        crate::operation::update_service::builders::UpdateServiceInputBuilder::default()
    }
}

/// A builder for [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateServiceInputBuilder {
    pub(crate) service_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_configuration: ::std::option::Option<crate::types::SourceConfiguration>,
    pub(crate) instance_configuration: ::std::option::Option<crate::types::InstanceConfiguration>,
    pub(crate) auto_scaling_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) health_check_configuration: ::std::option::Option<crate::types::HealthCheckConfiguration>,
    pub(crate) network_configuration: ::std::option::Option<crate::types::NetworkConfiguration>,
    pub(crate) observability_configuration: ::std::option::Option<crate::types::ServiceObservabilityConfiguration>,
}
impl UpdateServiceInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the App Runner service that you want to update.</p>
    /// This field is required.
    pub fn service_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the App Runner service that you want to update.</p>
    pub fn set_service_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the App Runner service that you want to update.</p>
    pub fn get_service_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_arn
    }
    /// <p>The source configuration to apply to the App Runner service.</p>
    /// <p>You can change the configuration of the code or image repository that the service uses. However, you can't switch from code to image or the other way around. This means that you must provide the same structure member of <code>SourceConfiguration</code> that you originally included when you created the service. Specifically, you can include either <code>CodeRepository</code> or <code>ImageRepository</code>. To update the source configuration, set the values to members of the structure that you include.</p>
    pub fn source_configuration(mut self, input: crate::types::SourceConfiguration) -> Self {
        self.source_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source configuration to apply to the App Runner service.</p>
    /// <p>You can change the configuration of the code or image repository that the service uses. However, you can't switch from code to image or the other way around. This means that you must provide the same structure member of <code>SourceConfiguration</code> that you originally included when you created the service. Specifically, you can include either <code>CodeRepository</code> or <code>ImageRepository</code>. To update the source configuration, set the values to members of the structure that you include.</p>
    pub fn set_source_configuration(mut self, input: ::std::option::Option<crate::types::SourceConfiguration>) -> Self {
        self.source_configuration = input;
        self
    }
    /// <p>The source configuration to apply to the App Runner service.</p>
    /// <p>You can change the configuration of the code or image repository that the service uses. However, you can't switch from code to image or the other way around. This means that you must provide the same structure member of <code>SourceConfiguration</code> that you originally included when you created the service. Specifically, you can include either <code>CodeRepository</code> or <code>ImageRepository</code>. To update the source configuration, set the values to members of the structure that you include.</p>
    pub fn get_source_configuration(&self) -> &::std::option::Option<crate::types::SourceConfiguration> {
        &self.source_configuration
    }
    /// <p>The runtime configuration to apply to instances (scaling units) of your service.</p>
    pub fn instance_configuration(mut self, input: crate::types::InstanceConfiguration) -> Self {
        self.instance_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The runtime configuration to apply to instances (scaling units) of your service.</p>
    pub fn set_instance_configuration(mut self, input: ::std::option::Option<crate::types::InstanceConfiguration>) -> Self {
        self.instance_configuration = input;
        self
    }
    /// <p>The runtime configuration to apply to instances (scaling units) of your service.</p>
    pub fn get_instance_configuration(&self) -> &::std::option::Option<crate::types::InstanceConfiguration> {
        &self.instance_configuration
    }
    /// <p>The Amazon Resource Name (ARN) of an App Runner automatic scaling configuration resource that you want to associate with the App Runner service.</p>
    pub fn auto_scaling_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_scaling_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an App Runner automatic scaling configuration resource that you want to associate with the App Runner service.</p>
    pub fn set_auto_scaling_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_scaling_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an App Runner automatic scaling configuration resource that you want to associate with the App Runner service.</p>
    pub fn get_auto_scaling_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_scaling_configuration_arn
    }
    /// <p>The settings for the health check that App Runner performs to monitor the health of the App Runner service.</p>
    pub fn health_check_configuration(mut self, input: crate::types::HealthCheckConfiguration) -> Self {
        self.health_check_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The settings for the health check that App Runner performs to monitor the health of the App Runner service.</p>
    pub fn set_health_check_configuration(mut self, input: ::std::option::Option<crate::types::HealthCheckConfiguration>) -> Self {
        self.health_check_configuration = input;
        self
    }
    /// <p>The settings for the health check that App Runner performs to monitor the health of the App Runner service.</p>
    pub fn get_health_check_configuration(&self) -> &::std::option::Option<crate::types::HealthCheckConfiguration> {
        &self.health_check_configuration
    }
    /// <p>Configuration settings related to network traffic of the web application that the App Runner service runs.</p>
    pub fn network_configuration(mut self, input: crate::types::NetworkConfiguration) -> Self {
        self.network_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration settings related to network traffic of the web application that the App Runner service runs.</p>
    pub fn set_network_configuration(mut self, input: ::std::option::Option<crate::types::NetworkConfiguration>) -> Self {
        self.network_configuration = input;
        self
    }
    /// <p>Configuration settings related to network traffic of the web application that the App Runner service runs.</p>
    pub fn get_network_configuration(&self) -> &::std::option::Option<crate::types::NetworkConfiguration> {
        &self.network_configuration
    }
    /// <p>The observability configuration of your service.</p>
    pub fn observability_configuration(mut self, input: crate::types::ServiceObservabilityConfiguration) -> Self {
        self.observability_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The observability configuration of your service.</p>
    pub fn set_observability_configuration(mut self, input: ::std::option::Option<crate::types::ServiceObservabilityConfiguration>) -> Self {
        self.observability_configuration = input;
        self
    }
    /// <p>The observability configuration of your service.</p>
    pub fn get_observability_configuration(&self) -> &::std::option::Option<crate::types::ServiceObservabilityConfiguration> {
        &self.observability_configuration
    }
    /// Consumes the builder and constructs a [`UpdateServiceInput`](crate::operation::update_service::UpdateServiceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_service::UpdateServiceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_service::UpdateServiceInput {
            service_arn: self.service_arn,
            source_configuration: self.source_configuration,
            instance_configuration: self.instance_configuration,
            auto_scaling_configuration_arn: self.auto_scaling_configuration_arn,
            health_check_configuration: self.health_check_configuration,
            network_configuration: self.network_configuration,
            observability_configuration: self.observability_configuration,
        })
    }
}
