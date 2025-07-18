// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateApplicationInput {
    /// <p>The name of the application.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon EMR release associated with the application.</p>
    pub release_label: ::std::option::Option<::std::string::String>,
    /// <p>The type of application you want to start, such as Spark or Hive.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The client idempotency token of the application to create. Its value must be unique for each request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The capacity to initialize when the application is created.</p>
    pub initial_capacity: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::InitialCapacityConfig>>,
    /// <p>The maximum capacity to allocate when the application is created. This is cumulative across all workers at any given point in time, not just when an application is created. No new resources will be created once any one of the defined limits is hit.</p>
    pub maximum_capacity: ::std::option::Option<crate::types::MaximumAllowedResources>,
    /// <p>The tags assigned to the application.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The configuration for an application to automatically start on job submission.</p>
    pub auto_start_configuration: ::std::option::Option<crate::types::AutoStartConfig>,
    /// <p>The configuration for an application to automatically stop after a certain amount of time being idle.</p>
    pub auto_stop_configuration: ::std::option::Option<crate::types::AutoStopConfig>,
    /// <p>The network configuration for customer VPC connectivity.</p>
    pub network_configuration: ::std::option::Option<crate::types::NetworkConfiguration>,
    /// <p>The CPU architecture of an application.</p>
    pub architecture: ::std::option::Option<crate::types::Architecture>,
    /// <p>The image configuration for all worker types. You can either set this parameter or <code>imageConfiguration</code> for each worker type in <code>workerTypeSpecifications</code>.</p>
    pub image_configuration: ::std::option::Option<crate::types::ImageConfigurationInput>,
    /// <p>The key-value pairs that specify worker type to <code>WorkerTypeSpecificationInput</code>. This parameter must contain all valid worker types for a Spark or Hive application. Valid worker types include <code>Driver</code> and <code>Executor</code> for Spark applications and <code>HiveDriver</code> and <code>TezTask</code> for Hive applications. You can either set image details in this parameter for each worker type, or in <code>imageConfiguration</code> for all worker types.</p>
    pub worker_type_specifications:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::WorkerTypeSpecificationInput>>,
    /// <p>The <a href="https://docs.aws.amazon.com/emr-serverless/latest/APIReference/API_Configuration.html">Configuration</a> specifications to use when creating an application. Each configuration consists of a classification and properties. This configuration is applied to all the job runs submitted under the application.</p>
    pub runtime_configuration: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>,
    /// <p>The configuration setting for monitoring.</p>
    pub monitoring_configuration: ::std::option::Option<crate::types::MonitoringConfiguration>,
    /// <p>The interactive configuration object that enables the interactive use cases to use when running an application.</p>
    pub interactive_configuration: ::std::option::Option<crate::types::InteractiveConfiguration>,
    /// <p>The scheduler configuration for batch and streaming jobs running on this application. Supported with release labels emr-7.0.0 and above.</p>
    pub scheduler_configuration: ::std::option::Option<crate::types::SchedulerConfiguration>,
    /// <p>The IAM Identity Center Configuration accepts the Identity Center instance parameter required to enable trusted identity propagation. This configuration allows identity propagation between integrated services and the Identity Center instance.</p>
    pub identity_center_configuration: ::std::option::Option<crate::types::IdentityCenterConfigurationInput>,
}
impl CreateApplicationInput {
    /// <p>The name of the application.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon EMR release associated with the application.</p>
    pub fn release_label(&self) -> ::std::option::Option<&str> {
        self.release_label.as_deref()
    }
    /// <p>The type of application you want to start, such as Spark or Hive.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The client idempotency token of the application to create. Its value must be unique for each request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The capacity to initialize when the application is created.</p>
    pub fn initial_capacity(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::InitialCapacityConfig>> {
        self.initial_capacity.as_ref()
    }
    /// <p>The maximum capacity to allocate when the application is created. This is cumulative across all workers at any given point in time, not just when an application is created. No new resources will be created once any one of the defined limits is hit.</p>
    pub fn maximum_capacity(&self) -> ::std::option::Option<&crate::types::MaximumAllowedResources> {
        self.maximum_capacity.as_ref()
    }
    /// <p>The tags assigned to the application.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>The configuration for an application to automatically start on job submission.</p>
    pub fn auto_start_configuration(&self) -> ::std::option::Option<&crate::types::AutoStartConfig> {
        self.auto_start_configuration.as_ref()
    }
    /// <p>The configuration for an application to automatically stop after a certain amount of time being idle.</p>
    pub fn auto_stop_configuration(&self) -> ::std::option::Option<&crate::types::AutoStopConfig> {
        self.auto_stop_configuration.as_ref()
    }
    /// <p>The network configuration for customer VPC connectivity.</p>
    pub fn network_configuration(&self) -> ::std::option::Option<&crate::types::NetworkConfiguration> {
        self.network_configuration.as_ref()
    }
    /// <p>The CPU architecture of an application.</p>
    pub fn architecture(&self) -> ::std::option::Option<&crate::types::Architecture> {
        self.architecture.as_ref()
    }
    /// <p>The image configuration for all worker types. You can either set this parameter or <code>imageConfiguration</code> for each worker type in <code>workerTypeSpecifications</code>.</p>
    pub fn image_configuration(&self) -> ::std::option::Option<&crate::types::ImageConfigurationInput> {
        self.image_configuration.as_ref()
    }
    /// <p>The key-value pairs that specify worker type to <code>WorkerTypeSpecificationInput</code>. This parameter must contain all valid worker types for a Spark or Hive application. Valid worker types include <code>Driver</code> and <code>Executor</code> for Spark applications and <code>HiveDriver</code> and <code>TezTask</code> for Hive applications. You can either set image details in this parameter for each worker type, or in <code>imageConfiguration</code> for all worker types.</p>
    pub fn worker_type_specifications(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::WorkerTypeSpecificationInput>> {
        self.worker_type_specifications.as_ref()
    }
    /// <p>The <a href="https://docs.aws.amazon.com/emr-serverless/latest/APIReference/API_Configuration.html">Configuration</a> specifications to use when creating an application. Each configuration consists of a classification and properties. This configuration is applied to all the job runs submitted under the application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.runtime_configuration.is_none()`.
    pub fn runtime_configuration(&self) -> &[crate::types::Configuration] {
        self.runtime_configuration.as_deref().unwrap_or_default()
    }
    /// <p>The configuration setting for monitoring.</p>
    pub fn monitoring_configuration(&self) -> ::std::option::Option<&crate::types::MonitoringConfiguration> {
        self.monitoring_configuration.as_ref()
    }
    /// <p>The interactive configuration object that enables the interactive use cases to use when running an application.</p>
    pub fn interactive_configuration(&self) -> ::std::option::Option<&crate::types::InteractiveConfiguration> {
        self.interactive_configuration.as_ref()
    }
    /// <p>The scheduler configuration for batch and streaming jobs running on this application. Supported with release labels emr-7.0.0 and above.</p>
    pub fn scheduler_configuration(&self) -> ::std::option::Option<&crate::types::SchedulerConfiguration> {
        self.scheduler_configuration.as_ref()
    }
    /// <p>The IAM Identity Center Configuration accepts the Identity Center instance parameter required to enable trusted identity propagation. This configuration allows identity propagation between integrated services and the Identity Center instance.</p>
    pub fn identity_center_configuration(&self) -> ::std::option::Option<&crate::types::IdentityCenterConfigurationInput> {
        self.identity_center_configuration.as_ref()
    }
}
impl CreateApplicationInput {
    /// Creates a new builder-style object to manufacture [`CreateApplicationInput`](crate::operation::create_application::CreateApplicationInput).
    pub fn builder() -> crate::operation::create_application::builders::CreateApplicationInputBuilder {
        crate::operation::create_application::builders::CreateApplicationInputBuilder::default()
    }
}

/// A builder for [`CreateApplicationInput`](crate::operation::create_application::CreateApplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateApplicationInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) release_label: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) initial_capacity: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::InitialCapacityConfig>>,
    pub(crate) maximum_capacity: ::std::option::Option<crate::types::MaximumAllowedResources>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) auto_start_configuration: ::std::option::Option<crate::types::AutoStartConfig>,
    pub(crate) auto_stop_configuration: ::std::option::Option<crate::types::AutoStopConfig>,
    pub(crate) network_configuration: ::std::option::Option<crate::types::NetworkConfiguration>,
    pub(crate) architecture: ::std::option::Option<crate::types::Architecture>,
    pub(crate) image_configuration: ::std::option::Option<crate::types::ImageConfigurationInput>,
    pub(crate) worker_type_specifications:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::WorkerTypeSpecificationInput>>,
    pub(crate) runtime_configuration: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>,
    pub(crate) monitoring_configuration: ::std::option::Option<crate::types::MonitoringConfiguration>,
    pub(crate) interactive_configuration: ::std::option::Option<crate::types::InteractiveConfiguration>,
    pub(crate) scheduler_configuration: ::std::option::Option<crate::types::SchedulerConfiguration>,
    pub(crate) identity_center_configuration: ::std::option::Option<crate::types::IdentityCenterConfigurationInput>,
}
impl CreateApplicationInputBuilder {
    /// <p>The name of the application.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the application.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the application.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon EMR release associated with the application.</p>
    /// This field is required.
    pub fn release_label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.release_label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon EMR release associated with the application.</p>
    pub fn set_release_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.release_label = input;
        self
    }
    /// <p>The Amazon EMR release associated with the application.</p>
    pub fn get_release_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.release_label
    }
    /// <p>The type of application you want to start, such as Spark or Hive.</p>
    /// This field is required.
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of application you want to start, such as Spark or Hive.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of application you want to start, such as Spark or Hive.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The client idempotency token of the application to create. Its value must be unique for each request.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The client idempotency token of the application to create. Its value must be unique for each request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>The client idempotency token of the application to create. Its value must be unique for each request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Adds a key-value pair to `initial_capacity`.
    ///
    /// To override the contents of this collection use [`set_initial_capacity`](Self::set_initial_capacity).
    ///
    /// <p>The capacity to initialize when the application is created.</p>
    pub fn initial_capacity(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::InitialCapacityConfig) -> Self {
        let mut hash_map = self.initial_capacity.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.initial_capacity = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The capacity to initialize when the application is created.</p>
    pub fn set_initial_capacity(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::InitialCapacityConfig>>,
    ) -> Self {
        self.initial_capacity = input;
        self
    }
    /// <p>The capacity to initialize when the application is created.</p>
    pub fn get_initial_capacity(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::InitialCapacityConfig>> {
        &self.initial_capacity
    }
    /// <p>The maximum capacity to allocate when the application is created. This is cumulative across all workers at any given point in time, not just when an application is created. No new resources will be created once any one of the defined limits is hit.</p>
    pub fn maximum_capacity(mut self, input: crate::types::MaximumAllowedResources) -> Self {
        self.maximum_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum capacity to allocate when the application is created. This is cumulative across all workers at any given point in time, not just when an application is created. No new resources will be created once any one of the defined limits is hit.</p>
    pub fn set_maximum_capacity(mut self, input: ::std::option::Option<crate::types::MaximumAllowedResources>) -> Self {
        self.maximum_capacity = input;
        self
    }
    /// <p>The maximum capacity to allocate when the application is created. This is cumulative across all workers at any given point in time, not just when an application is created. No new resources will be created once any one of the defined limits is hit.</p>
    pub fn get_maximum_capacity(&self) -> &::std::option::Option<crate::types::MaximumAllowedResources> {
        &self.maximum_capacity
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags assigned to the application.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags assigned to the application.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags assigned to the application.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>The configuration for an application to automatically start on job submission.</p>
    pub fn auto_start_configuration(mut self, input: crate::types::AutoStartConfig) -> Self {
        self.auto_start_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for an application to automatically start on job submission.</p>
    pub fn set_auto_start_configuration(mut self, input: ::std::option::Option<crate::types::AutoStartConfig>) -> Self {
        self.auto_start_configuration = input;
        self
    }
    /// <p>The configuration for an application to automatically start on job submission.</p>
    pub fn get_auto_start_configuration(&self) -> &::std::option::Option<crate::types::AutoStartConfig> {
        &self.auto_start_configuration
    }
    /// <p>The configuration for an application to automatically stop after a certain amount of time being idle.</p>
    pub fn auto_stop_configuration(mut self, input: crate::types::AutoStopConfig) -> Self {
        self.auto_stop_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for an application to automatically stop after a certain amount of time being idle.</p>
    pub fn set_auto_stop_configuration(mut self, input: ::std::option::Option<crate::types::AutoStopConfig>) -> Self {
        self.auto_stop_configuration = input;
        self
    }
    /// <p>The configuration for an application to automatically stop after a certain amount of time being idle.</p>
    pub fn get_auto_stop_configuration(&self) -> &::std::option::Option<crate::types::AutoStopConfig> {
        &self.auto_stop_configuration
    }
    /// <p>The network configuration for customer VPC connectivity.</p>
    pub fn network_configuration(mut self, input: crate::types::NetworkConfiguration) -> Self {
        self.network_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The network configuration for customer VPC connectivity.</p>
    pub fn set_network_configuration(mut self, input: ::std::option::Option<crate::types::NetworkConfiguration>) -> Self {
        self.network_configuration = input;
        self
    }
    /// <p>The network configuration for customer VPC connectivity.</p>
    pub fn get_network_configuration(&self) -> &::std::option::Option<crate::types::NetworkConfiguration> {
        &self.network_configuration
    }
    /// <p>The CPU architecture of an application.</p>
    pub fn architecture(mut self, input: crate::types::Architecture) -> Self {
        self.architecture = ::std::option::Option::Some(input);
        self
    }
    /// <p>The CPU architecture of an application.</p>
    pub fn set_architecture(mut self, input: ::std::option::Option<crate::types::Architecture>) -> Self {
        self.architecture = input;
        self
    }
    /// <p>The CPU architecture of an application.</p>
    pub fn get_architecture(&self) -> &::std::option::Option<crate::types::Architecture> {
        &self.architecture
    }
    /// <p>The image configuration for all worker types. You can either set this parameter or <code>imageConfiguration</code> for each worker type in <code>workerTypeSpecifications</code>.</p>
    pub fn image_configuration(mut self, input: crate::types::ImageConfigurationInput) -> Self {
        self.image_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image configuration for all worker types. You can either set this parameter or <code>imageConfiguration</code> for each worker type in <code>workerTypeSpecifications</code>.</p>
    pub fn set_image_configuration(mut self, input: ::std::option::Option<crate::types::ImageConfigurationInput>) -> Self {
        self.image_configuration = input;
        self
    }
    /// <p>The image configuration for all worker types. You can either set this parameter or <code>imageConfiguration</code> for each worker type in <code>workerTypeSpecifications</code>.</p>
    pub fn get_image_configuration(&self) -> &::std::option::Option<crate::types::ImageConfigurationInput> {
        &self.image_configuration
    }
    /// Adds a key-value pair to `worker_type_specifications`.
    ///
    /// To override the contents of this collection use [`set_worker_type_specifications`](Self::set_worker_type_specifications).
    ///
    /// <p>The key-value pairs that specify worker type to <code>WorkerTypeSpecificationInput</code>. This parameter must contain all valid worker types for a Spark or Hive application. Valid worker types include <code>Driver</code> and <code>Executor</code> for Spark applications and <code>HiveDriver</code> and <code>TezTask</code> for Hive applications. You can either set image details in this parameter for each worker type, or in <code>imageConfiguration</code> for all worker types.</p>
    pub fn worker_type_specifications(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: crate::types::WorkerTypeSpecificationInput,
    ) -> Self {
        let mut hash_map = self.worker_type_specifications.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.worker_type_specifications = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The key-value pairs that specify worker type to <code>WorkerTypeSpecificationInput</code>. This parameter must contain all valid worker types for a Spark or Hive application. Valid worker types include <code>Driver</code> and <code>Executor</code> for Spark applications and <code>HiveDriver</code> and <code>TezTask</code> for Hive applications. You can either set image details in this parameter for each worker type, or in <code>imageConfiguration</code> for all worker types.</p>
    pub fn set_worker_type_specifications(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::WorkerTypeSpecificationInput>>,
    ) -> Self {
        self.worker_type_specifications = input;
        self
    }
    /// <p>The key-value pairs that specify worker type to <code>WorkerTypeSpecificationInput</code>. This parameter must contain all valid worker types for a Spark or Hive application. Valid worker types include <code>Driver</code> and <code>Executor</code> for Spark applications and <code>HiveDriver</code> and <code>TezTask</code> for Hive applications. You can either set image details in this parameter for each worker type, or in <code>imageConfiguration</code> for all worker types.</p>
    pub fn get_worker_type_specifications(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::WorkerTypeSpecificationInput>> {
        &self.worker_type_specifications
    }
    /// Appends an item to `runtime_configuration`.
    ///
    /// To override the contents of this collection use [`set_runtime_configuration`](Self::set_runtime_configuration).
    ///
    /// <p>The <a href="https://docs.aws.amazon.com/emr-serverless/latest/APIReference/API_Configuration.html">Configuration</a> specifications to use when creating an application. Each configuration consists of a classification and properties. This configuration is applied to all the job runs submitted under the application.</p>
    pub fn runtime_configuration(mut self, input: crate::types::Configuration) -> Self {
        let mut v = self.runtime_configuration.unwrap_or_default();
        v.push(input);
        self.runtime_configuration = ::std::option::Option::Some(v);
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/emr-serverless/latest/APIReference/API_Configuration.html">Configuration</a> specifications to use when creating an application. Each configuration consists of a classification and properties. This configuration is applied to all the job runs submitted under the application.</p>
    pub fn set_runtime_configuration(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Configuration>>) -> Self {
        self.runtime_configuration = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/emr-serverless/latest/APIReference/API_Configuration.html">Configuration</a> specifications to use when creating an application. Each configuration consists of a classification and properties. This configuration is applied to all the job runs submitted under the application.</p>
    pub fn get_runtime_configuration(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Configuration>> {
        &self.runtime_configuration
    }
    /// <p>The configuration setting for monitoring.</p>
    pub fn monitoring_configuration(mut self, input: crate::types::MonitoringConfiguration) -> Self {
        self.monitoring_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration setting for monitoring.</p>
    pub fn set_monitoring_configuration(mut self, input: ::std::option::Option<crate::types::MonitoringConfiguration>) -> Self {
        self.monitoring_configuration = input;
        self
    }
    /// <p>The configuration setting for monitoring.</p>
    pub fn get_monitoring_configuration(&self) -> &::std::option::Option<crate::types::MonitoringConfiguration> {
        &self.monitoring_configuration
    }
    /// <p>The interactive configuration object that enables the interactive use cases to use when running an application.</p>
    pub fn interactive_configuration(mut self, input: crate::types::InteractiveConfiguration) -> Self {
        self.interactive_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The interactive configuration object that enables the interactive use cases to use when running an application.</p>
    pub fn set_interactive_configuration(mut self, input: ::std::option::Option<crate::types::InteractiveConfiguration>) -> Self {
        self.interactive_configuration = input;
        self
    }
    /// <p>The interactive configuration object that enables the interactive use cases to use when running an application.</p>
    pub fn get_interactive_configuration(&self) -> &::std::option::Option<crate::types::InteractiveConfiguration> {
        &self.interactive_configuration
    }
    /// <p>The scheduler configuration for batch and streaming jobs running on this application. Supported with release labels emr-7.0.0 and above.</p>
    pub fn scheduler_configuration(mut self, input: crate::types::SchedulerConfiguration) -> Self {
        self.scheduler_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The scheduler configuration for batch and streaming jobs running on this application. Supported with release labels emr-7.0.0 and above.</p>
    pub fn set_scheduler_configuration(mut self, input: ::std::option::Option<crate::types::SchedulerConfiguration>) -> Self {
        self.scheduler_configuration = input;
        self
    }
    /// <p>The scheduler configuration for batch and streaming jobs running on this application. Supported with release labels emr-7.0.0 and above.</p>
    pub fn get_scheduler_configuration(&self) -> &::std::option::Option<crate::types::SchedulerConfiguration> {
        &self.scheduler_configuration
    }
    /// <p>The IAM Identity Center Configuration accepts the Identity Center instance parameter required to enable trusted identity propagation. This configuration allows identity propagation between integrated services and the Identity Center instance.</p>
    pub fn identity_center_configuration(mut self, input: crate::types::IdentityCenterConfigurationInput) -> Self {
        self.identity_center_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The IAM Identity Center Configuration accepts the Identity Center instance parameter required to enable trusted identity propagation. This configuration allows identity propagation between integrated services and the Identity Center instance.</p>
    pub fn set_identity_center_configuration(mut self, input: ::std::option::Option<crate::types::IdentityCenterConfigurationInput>) -> Self {
        self.identity_center_configuration = input;
        self
    }
    /// <p>The IAM Identity Center Configuration accepts the Identity Center instance parameter required to enable trusted identity propagation. This configuration allows identity propagation between integrated services and the Identity Center instance.</p>
    pub fn get_identity_center_configuration(&self) -> &::std::option::Option<crate::types::IdentityCenterConfigurationInput> {
        &self.identity_center_configuration
    }
    /// Consumes the builder and constructs a [`CreateApplicationInput`](crate::operation::create_application::CreateApplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_application::CreateApplicationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_application::CreateApplicationInput {
            name: self.name,
            release_label: self.release_label,
            r#type: self.r#type,
            client_token: self.client_token,
            initial_capacity: self.initial_capacity,
            maximum_capacity: self.maximum_capacity,
            tags: self.tags,
            auto_start_configuration: self.auto_start_configuration,
            auto_stop_configuration: self.auto_stop_configuration,
            network_configuration: self.network_configuration,
            architecture: self.architecture,
            image_configuration: self.image_configuration,
            worker_type_specifications: self.worker_type_specifications,
            runtime_configuration: self.runtime_configuration,
            monitoring_configuration: self.monitoring_configuration,
            interactive_configuration: self.interactive_configuration,
            scheduler_configuration: self.scheduler_configuration,
            identity_center_configuration: self.identity_center_configuration,
        })
    }
}
