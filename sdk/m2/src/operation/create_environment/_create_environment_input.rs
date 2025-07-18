// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateEnvironmentInput {
    /// <p>The name of the runtime environment. Must be unique within the account.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of instance for the runtime environment.</p>
    pub instance_type: ::std::option::Option<::std::string::String>,
    /// <p>The description of the runtime environment.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The engine type for the runtime environment.</p>
    pub engine_type: ::std::option::Option<crate::types::EngineType>,
    /// <p>The version of the engine type for the runtime environment.</p>
    pub engine_version: ::std::option::Option<::std::string::String>,
    /// <p>The list of subnets associated with the VPC for this runtime environment.</p>
    pub subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The list of security groups for the VPC associated with this runtime environment.</p>
    pub security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Optional. The storage configurations for this runtime environment.</p>
    pub storage_configurations: ::std::option::Option<::std::vec::Vec<crate::types::StorageConfiguration>>,
    /// <p>Specifies whether the runtime environment is publicly accessible.</p>
    pub publicly_accessible: ::std::option::Option<bool>,
    /// <p>The details of a high availability configuration for this runtime environment.</p>
    pub high_availability_config: ::std::option::Option<crate::types::HighAvailabilityConfig>,
    /// <p>The tags for the runtime environment.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>Configures the maintenance window that you want for the runtime environment. The maintenance window must have the format <code>ddd:hh24:mi-ddd:hh24:mi</code> and must be less than 24 hours. The following two examples are valid maintenance windows: <code>sun:23:45-mon:00:15</code> or <code>sat:01:00-sat:03:00</code>.</p>
    /// <p>If you do not provide a value, a random system-generated value will be assigned.</p>
    pub preferred_maintenance_window: ::std::option::Option<::std::string::String>,
    /// <p>The network type required for the runtime environment.</p>
    pub network_type: ::std::option::Option<crate::types::NetworkType>,
    /// <p>Unique, case-sensitive identifier you provide to ensure the idempotency of the request to create an environment. The service generates the clientToken when the API call is triggered. The token expires after one hour, so if you retry the API within this timeframe with the same clientToken, you will get the same response. The service also handles deleting the clientToken after it expires.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of a customer managed key.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
}
impl CreateEnvironmentInput {
    /// <p>The name of the runtime environment. Must be unique within the account.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of instance for the runtime environment.</p>
    pub fn instance_type(&self) -> ::std::option::Option<&str> {
        self.instance_type.as_deref()
    }
    /// <p>The description of the runtime environment.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The engine type for the runtime environment.</p>
    pub fn engine_type(&self) -> ::std::option::Option<&crate::types::EngineType> {
        self.engine_type.as_ref()
    }
    /// <p>The version of the engine type for the runtime environment.</p>
    pub fn engine_version(&self) -> ::std::option::Option<&str> {
        self.engine_version.as_deref()
    }
    /// <p>The list of subnets associated with the VPC for this runtime environment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ids.is_none()`.
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        self.subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The list of security groups for the VPC associated with this runtime environment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_ids.is_none()`.
    pub fn security_group_ids(&self) -> &[::std::string::String] {
        self.security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>Optional. The storage configurations for this runtime environment.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.storage_configurations.is_none()`.
    pub fn storage_configurations(&self) -> &[crate::types::StorageConfiguration] {
        self.storage_configurations.as_deref().unwrap_or_default()
    }
    /// <p>Specifies whether the runtime environment is publicly accessible.</p>
    pub fn publicly_accessible(&self) -> ::std::option::Option<bool> {
        self.publicly_accessible
    }
    /// <p>The details of a high availability configuration for this runtime environment.</p>
    pub fn high_availability_config(&self) -> ::std::option::Option<&crate::types::HighAvailabilityConfig> {
        self.high_availability_config.as_ref()
    }
    /// <p>The tags for the runtime environment.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>Configures the maintenance window that you want for the runtime environment. The maintenance window must have the format <code>ddd:hh24:mi-ddd:hh24:mi</code> and must be less than 24 hours. The following two examples are valid maintenance windows: <code>sun:23:45-mon:00:15</code> or <code>sat:01:00-sat:03:00</code>.</p>
    /// <p>If you do not provide a value, a random system-generated value will be assigned.</p>
    pub fn preferred_maintenance_window(&self) -> ::std::option::Option<&str> {
        self.preferred_maintenance_window.as_deref()
    }
    /// <p>The network type required for the runtime environment.</p>
    pub fn network_type(&self) -> ::std::option::Option<&crate::types::NetworkType> {
        self.network_type.as_ref()
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure the idempotency of the request to create an environment. The service generates the clientToken when the API call is triggered. The token expires after one hour, so if you retry the API within this timeframe with the same clientToken, you will get the same response. The service also handles deleting the clientToken after it expires.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>The identifier of a customer managed key.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
}
impl CreateEnvironmentInput {
    /// Creates a new builder-style object to manufacture [`CreateEnvironmentInput`](crate::operation::create_environment::CreateEnvironmentInput).
    pub fn builder() -> crate::operation::create_environment::builders::CreateEnvironmentInputBuilder {
        crate::operation::create_environment::builders::CreateEnvironmentInputBuilder::default()
    }
}

/// A builder for [`CreateEnvironmentInput`](crate::operation::create_environment::CreateEnvironmentInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateEnvironmentInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) instance_type: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) engine_type: ::std::option::Option<crate::types::EngineType>,
    pub(crate) engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) storage_configurations: ::std::option::Option<::std::vec::Vec<crate::types::StorageConfiguration>>,
    pub(crate) publicly_accessible: ::std::option::Option<bool>,
    pub(crate) high_availability_config: ::std::option::Option<crate::types::HighAvailabilityConfig>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) preferred_maintenance_window: ::std::option::Option<::std::string::String>,
    pub(crate) network_type: ::std::option::Option<crate::types::NetworkType>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
}
impl CreateEnvironmentInputBuilder {
    /// <p>The name of the runtime environment. Must be unique within the account.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the runtime environment. Must be unique within the account.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the runtime environment. Must be unique within the account.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of instance for the runtime environment.</p>
    /// This field is required.
    pub fn instance_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of instance for the runtime environment.</p>
    pub fn set_instance_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_type = input;
        self
    }
    /// <p>The type of instance for the runtime environment.</p>
    pub fn get_instance_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_type
    }
    /// <p>The description of the runtime environment.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the runtime environment.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the runtime environment.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The engine type for the runtime environment.</p>
    /// This field is required.
    pub fn engine_type(mut self, input: crate::types::EngineType) -> Self {
        self.engine_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The engine type for the runtime environment.</p>
    pub fn set_engine_type(mut self, input: ::std::option::Option<crate::types::EngineType>) -> Self {
        self.engine_type = input;
        self
    }
    /// <p>The engine type for the runtime environment.</p>
    pub fn get_engine_type(&self) -> &::std::option::Option<crate::types::EngineType> {
        &self.engine_type
    }
    /// <p>The version of the engine type for the runtime environment.</p>
    pub fn engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the engine type for the runtime environment.</p>
    pub fn set_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine_version = input;
        self
    }
    /// <p>The version of the engine type for the runtime environment.</p>
    pub fn get_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine_version
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>The list of subnets associated with the VPC for this runtime environment.</p>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of subnets associated with the VPC for this runtime environment.</p>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>The list of subnets associated with the VPC for this runtime environment.</p>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// Appends an item to `security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_security_group_ids`](Self::set_security_group_ids).
    ///
    /// <p>The list of security groups for the VPC associated with this runtime environment.</p>
    pub fn security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of security groups for the VPC associated with this runtime environment.</p>
    pub fn set_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_ids = input;
        self
    }
    /// <p>The list of security groups for the VPC associated with this runtime environment.</p>
    pub fn get_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_ids
    }
    /// Appends an item to `storage_configurations`.
    ///
    /// To override the contents of this collection use [`set_storage_configurations`](Self::set_storage_configurations).
    ///
    /// <p>Optional. The storage configurations for this runtime environment.</p>
    pub fn storage_configurations(mut self, input: crate::types::StorageConfiguration) -> Self {
        let mut v = self.storage_configurations.unwrap_or_default();
        v.push(input);
        self.storage_configurations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Optional. The storage configurations for this runtime environment.</p>
    pub fn set_storage_configurations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StorageConfiguration>>) -> Self {
        self.storage_configurations = input;
        self
    }
    /// <p>Optional. The storage configurations for this runtime environment.</p>
    pub fn get_storage_configurations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StorageConfiguration>> {
        &self.storage_configurations
    }
    /// <p>Specifies whether the runtime environment is publicly accessible.</p>
    pub fn publicly_accessible(mut self, input: bool) -> Self {
        self.publicly_accessible = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the runtime environment is publicly accessible.</p>
    pub fn set_publicly_accessible(mut self, input: ::std::option::Option<bool>) -> Self {
        self.publicly_accessible = input;
        self
    }
    /// <p>Specifies whether the runtime environment is publicly accessible.</p>
    pub fn get_publicly_accessible(&self) -> &::std::option::Option<bool> {
        &self.publicly_accessible
    }
    /// <p>The details of a high availability configuration for this runtime environment.</p>
    pub fn high_availability_config(mut self, input: crate::types::HighAvailabilityConfig) -> Self {
        self.high_availability_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The details of a high availability configuration for this runtime environment.</p>
    pub fn set_high_availability_config(mut self, input: ::std::option::Option<crate::types::HighAvailabilityConfig>) -> Self {
        self.high_availability_config = input;
        self
    }
    /// <p>The details of a high availability configuration for this runtime environment.</p>
    pub fn get_high_availability_config(&self) -> &::std::option::Option<crate::types::HighAvailabilityConfig> {
        &self.high_availability_config
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags for the runtime environment.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The tags for the runtime environment.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags for the runtime environment.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>Configures the maintenance window that you want for the runtime environment. The maintenance window must have the format <code>ddd:hh24:mi-ddd:hh24:mi</code> and must be less than 24 hours. The following two examples are valid maintenance windows: <code>sun:23:45-mon:00:15</code> or <code>sat:01:00-sat:03:00</code>.</p>
    /// <p>If you do not provide a value, a random system-generated value will be assigned.</p>
    pub fn preferred_maintenance_window(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.preferred_maintenance_window = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Configures the maintenance window that you want for the runtime environment. The maintenance window must have the format <code>ddd:hh24:mi-ddd:hh24:mi</code> and must be less than 24 hours. The following two examples are valid maintenance windows: <code>sun:23:45-mon:00:15</code> or <code>sat:01:00-sat:03:00</code>.</p>
    /// <p>If you do not provide a value, a random system-generated value will be assigned.</p>
    pub fn set_preferred_maintenance_window(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.preferred_maintenance_window = input;
        self
    }
    /// <p>Configures the maintenance window that you want for the runtime environment. The maintenance window must have the format <code>ddd:hh24:mi-ddd:hh24:mi</code> and must be less than 24 hours. The following two examples are valid maintenance windows: <code>sun:23:45-mon:00:15</code> or <code>sat:01:00-sat:03:00</code>.</p>
    /// <p>If you do not provide a value, a random system-generated value will be assigned.</p>
    pub fn get_preferred_maintenance_window(&self) -> &::std::option::Option<::std::string::String> {
        &self.preferred_maintenance_window
    }
    /// <p>The network type required for the runtime environment.</p>
    pub fn network_type(mut self, input: crate::types::NetworkType) -> Self {
        self.network_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The network type required for the runtime environment.</p>
    pub fn set_network_type(mut self, input: ::std::option::Option<crate::types::NetworkType>) -> Self {
        self.network_type = input;
        self
    }
    /// <p>The network type required for the runtime environment.</p>
    pub fn get_network_type(&self) -> &::std::option::Option<crate::types::NetworkType> {
        &self.network_type
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure the idempotency of the request to create an environment. The service generates the clientToken when the API call is triggered. The token expires after one hour, so if you retry the API within this timeframe with the same clientToken, you will get the same response. The service also handles deleting the clientToken after it expires.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure the idempotency of the request to create an environment. The service generates the clientToken when the API call is triggered. The token expires after one hour, so if you retry the API within this timeframe with the same clientToken, you will get the same response. The service also handles deleting the clientToken after it expires.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier you provide to ensure the idempotency of the request to create an environment. The service generates the clientToken when the API call is triggered. The token expires after one hour, so if you retry the API within this timeframe with the same clientToken, you will get the same response. The service also handles deleting the clientToken after it expires.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>The identifier of a customer managed key.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of a customer managed key.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The identifier of a customer managed key.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Consumes the builder and constructs a [`CreateEnvironmentInput`](crate::operation::create_environment::CreateEnvironmentInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_environment::CreateEnvironmentInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_environment::CreateEnvironmentInput {
            name: self.name,
            instance_type: self.instance_type,
            description: self.description,
            engine_type: self.engine_type,
            engine_version: self.engine_version,
            subnet_ids: self.subnet_ids,
            security_group_ids: self.security_group_ids,
            storage_configurations: self.storage_configurations,
            publicly_accessible: self.publicly_accessible,
            high_availability_config: self.high_availability_config,
            tags: self.tags,
            preferred_maintenance_window: self.preferred_maintenance_window,
            network_type: self.network_type,
            client_token: self.client_token,
            kms_key_id: self.kms_key_id,
        })
    }
}
