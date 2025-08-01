// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specific configuration settings for a Kafka schema registry.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KafkaSchemaRegistryConfig {
    /// <p>The URI for your schema registry. The correct URI format depends on the type of schema registry you're using.</p>
    /// <ul>
    /// <li>
    /// <p>For Glue schema registries, use the ARN of the registry.</p></li>
    /// <li>
    /// <p>For Confluent schema registries, use the URL of the registry.</p></li>
    /// </ul>
    pub schema_registry_uri: ::std::option::Option<::std::string::String>,
    /// <p>The record format that Lambda delivers to your function after schema validation.</p>
    /// <ul>
    /// <li>
    /// <p>Choose <code>JSON</code> to have Lambda deliver the record to your function as a standard JSON object.</p></li>
    /// <li>
    /// <p>Choose <code>SOURCE</code> to have Lambda deliver the record to your function in its original source format. Lambda removes all schema metadata, such as the schema ID, before sending the record to your function.</p></li>
    /// </ul>
    pub event_record_format: ::std::option::Option<crate::types::SchemaRegistryEventRecordFormat>,
    /// <p>An array of access configuration objects that tell Lambda how to authenticate with your schema registry.</p>
    pub access_configs: ::std::option::Option<::std::vec::Vec<crate::types::KafkaSchemaRegistryAccessConfig>>,
    /// <p>An array of schema validation configuration objects, which tell Lambda the message attributes you want to validate and filter using your schema registry.</p>
    pub schema_validation_configs: ::std::option::Option<::std::vec::Vec<crate::types::KafkaSchemaValidationConfig>>,
}
impl KafkaSchemaRegistryConfig {
    /// <p>The URI for your schema registry. The correct URI format depends on the type of schema registry you're using.</p>
    /// <ul>
    /// <li>
    /// <p>For Glue schema registries, use the ARN of the registry.</p></li>
    /// <li>
    /// <p>For Confluent schema registries, use the URL of the registry.</p></li>
    /// </ul>
    pub fn schema_registry_uri(&self) -> ::std::option::Option<&str> {
        self.schema_registry_uri.as_deref()
    }
    /// <p>The record format that Lambda delivers to your function after schema validation.</p>
    /// <ul>
    /// <li>
    /// <p>Choose <code>JSON</code> to have Lambda deliver the record to your function as a standard JSON object.</p></li>
    /// <li>
    /// <p>Choose <code>SOURCE</code> to have Lambda deliver the record to your function in its original source format. Lambda removes all schema metadata, such as the schema ID, before sending the record to your function.</p></li>
    /// </ul>
    pub fn event_record_format(&self) -> ::std::option::Option<&crate::types::SchemaRegistryEventRecordFormat> {
        self.event_record_format.as_ref()
    }
    /// <p>An array of access configuration objects that tell Lambda how to authenticate with your schema registry.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.access_configs.is_none()`.
    pub fn access_configs(&self) -> &[crate::types::KafkaSchemaRegistryAccessConfig] {
        self.access_configs.as_deref().unwrap_or_default()
    }
    /// <p>An array of schema validation configuration objects, which tell Lambda the message attributes you want to validate and filter using your schema registry.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.schema_validation_configs.is_none()`.
    pub fn schema_validation_configs(&self) -> &[crate::types::KafkaSchemaValidationConfig] {
        self.schema_validation_configs.as_deref().unwrap_or_default()
    }
}
impl KafkaSchemaRegistryConfig {
    /// Creates a new builder-style object to manufacture [`KafkaSchemaRegistryConfig`](crate::types::KafkaSchemaRegistryConfig).
    pub fn builder() -> crate::types::builders::KafkaSchemaRegistryConfigBuilder {
        crate::types::builders::KafkaSchemaRegistryConfigBuilder::default()
    }
}

/// A builder for [`KafkaSchemaRegistryConfig`](crate::types::KafkaSchemaRegistryConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KafkaSchemaRegistryConfigBuilder {
    pub(crate) schema_registry_uri: ::std::option::Option<::std::string::String>,
    pub(crate) event_record_format: ::std::option::Option<crate::types::SchemaRegistryEventRecordFormat>,
    pub(crate) access_configs: ::std::option::Option<::std::vec::Vec<crate::types::KafkaSchemaRegistryAccessConfig>>,
    pub(crate) schema_validation_configs: ::std::option::Option<::std::vec::Vec<crate::types::KafkaSchemaValidationConfig>>,
}
impl KafkaSchemaRegistryConfigBuilder {
    /// <p>The URI for your schema registry. The correct URI format depends on the type of schema registry you're using.</p>
    /// <ul>
    /// <li>
    /// <p>For Glue schema registries, use the ARN of the registry.</p></li>
    /// <li>
    /// <p>For Confluent schema registries, use the URL of the registry.</p></li>
    /// </ul>
    pub fn schema_registry_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.schema_registry_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URI for your schema registry. The correct URI format depends on the type of schema registry you're using.</p>
    /// <ul>
    /// <li>
    /// <p>For Glue schema registries, use the ARN of the registry.</p></li>
    /// <li>
    /// <p>For Confluent schema registries, use the URL of the registry.</p></li>
    /// </ul>
    pub fn set_schema_registry_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.schema_registry_uri = input;
        self
    }
    /// <p>The URI for your schema registry. The correct URI format depends on the type of schema registry you're using.</p>
    /// <ul>
    /// <li>
    /// <p>For Glue schema registries, use the ARN of the registry.</p></li>
    /// <li>
    /// <p>For Confluent schema registries, use the URL of the registry.</p></li>
    /// </ul>
    pub fn get_schema_registry_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.schema_registry_uri
    }
    /// <p>The record format that Lambda delivers to your function after schema validation.</p>
    /// <ul>
    /// <li>
    /// <p>Choose <code>JSON</code> to have Lambda deliver the record to your function as a standard JSON object.</p></li>
    /// <li>
    /// <p>Choose <code>SOURCE</code> to have Lambda deliver the record to your function in its original source format. Lambda removes all schema metadata, such as the schema ID, before sending the record to your function.</p></li>
    /// </ul>
    pub fn event_record_format(mut self, input: crate::types::SchemaRegistryEventRecordFormat) -> Self {
        self.event_record_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The record format that Lambda delivers to your function after schema validation.</p>
    /// <ul>
    /// <li>
    /// <p>Choose <code>JSON</code> to have Lambda deliver the record to your function as a standard JSON object.</p></li>
    /// <li>
    /// <p>Choose <code>SOURCE</code> to have Lambda deliver the record to your function in its original source format. Lambda removes all schema metadata, such as the schema ID, before sending the record to your function.</p></li>
    /// </ul>
    pub fn set_event_record_format(mut self, input: ::std::option::Option<crate::types::SchemaRegistryEventRecordFormat>) -> Self {
        self.event_record_format = input;
        self
    }
    /// <p>The record format that Lambda delivers to your function after schema validation.</p>
    /// <ul>
    /// <li>
    /// <p>Choose <code>JSON</code> to have Lambda deliver the record to your function as a standard JSON object.</p></li>
    /// <li>
    /// <p>Choose <code>SOURCE</code> to have Lambda deliver the record to your function in its original source format. Lambda removes all schema metadata, such as the schema ID, before sending the record to your function.</p></li>
    /// </ul>
    pub fn get_event_record_format(&self) -> &::std::option::Option<crate::types::SchemaRegistryEventRecordFormat> {
        &self.event_record_format
    }
    /// Appends an item to `access_configs`.
    ///
    /// To override the contents of this collection use [`set_access_configs`](Self::set_access_configs).
    ///
    /// <p>An array of access configuration objects that tell Lambda how to authenticate with your schema registry.</p>
    pub fn access_configs(mut self, input: crate::types::KafkaSchemaRegistryAccessConfig) -> Self {
        let mut v = self.access_configs.unwrap_or_default();
        v.push(input);
        self.access_configs = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of access configuration objects that tell Lambda how to authenticate with your schema registry.</p>
    pub fn set_access_configs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::KafkaSchemaRegistryAccessConfig>>) -> Self {
        self.access_configs = input;
        self
    }
    /// <p>An array of access configuration objects that tell Lambda how to authenticate with your schema registry.</p>
    pub fn get_access_configs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::KafkaSchemaRegistryAccessConfig>> {
        &self.access_configs
    }
    /// Appends an item to `schema_validation_configs`.
    ///
    /// To override the contents of this collection use [`set_schema_validation_configs`](Self::set_schema_validation_configs).
    ///
    /// <p>An array of schema validation configuration objects, which tell Lambda the message attributes you want to validate and filter using your schema registry.</p>
    pub fn schema_validation_configs(mut self, input: crate::types::KafkaSchemaValidationConfig) -> Self {
        let mut v = self.schema_validation_configs.unwrap_or_default();
        v.push(input);
        self.schema_validation_configs = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of schema validation configuration objects, which tell Lambda the message attributes you want to validate and filter using your schema registry.</p>
    pub fn set_schema_validation_configs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::KafkaSchemaValidationConfig>>) -> Self {
        self.schema_validation_configs = input;
        self
    }
    /// <p>An array of schema validation configuration objects, which tell Lambda the message attributes you want to validate and filter using your schema registry.</p>
    pub fn get_schema_validation_configs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::KafkaSchemaValidationConfig>> {
        &self.schema_validation_configs
    }
    /// Consumes the builder and constructs a [`KafkaSchemaRegistryConfig`](crate::types::KafkaSchemaRegistryConfig).
    pub fn build(self) -> crate::types::KafkaSchemaRegistryConfig {
        crate::types::KafkaSchemaRegistryConfig {
            schema_registry_uri: self.schema_registry_uri,
            event_record_format: self.event_record_format,
            access_configs: self.access_configs,
            schema_validation_configs: self.schema_validation_configs,
        }
    }
}
