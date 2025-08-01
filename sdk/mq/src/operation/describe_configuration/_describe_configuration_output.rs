// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeConfigurationOutput {
    /// <p>Required. The ARN of the configuration.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>Optional. The authentication strategy associated with the configuration. The default is SIMPLE.</p>
    pub authentication_strategy: ::std::option::Option<crate::types::AuthenticationStrategy>,
    /// <p>Required. The date and time of the configuration revision.</p>
    pub created: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Required. The description of the configuration.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Required. The type of broker engine. Currently, Amazon MQ supports ACTIVEMQ and RABBITMQ.</p>
    pub engine_type: ::std::option::Option<crate::types::EngineType>,
    /// <p>The broker engine version. Defaults to the latest available version for the specified broker engine type. For a list of supported engine versions, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p>
    pub engine_version: ::std::option::Option<::std::string::String>,
    /// <p>Required. The unique ID that Amazon MQ generates for the configuration.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>Required. The latest revision of the configuration.</p>
    pub latest_revision: ::std::option::Option<crate::types::ConfigurationRevision>,
    /// <p>Required. The name of the configuration. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The list of all tags associated with this configuration.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl DescribeConfigurationOutput {
    /// <p>Required. The ARN of the configuration.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>Optional. The authentication strategy associated with the configuration. The default is SIMPLE.</p>
    pub fn authentication_strategy(&self) -> ::std::option::Option<&crate::types::AuthenticationStrategy> {
        self.authentication_strategy.as_ref()
    }
    /// <p>Required. The date and time of the configuration revision.</p>
    pub fn created(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created.as_ref()
    }
    /// <p>Required. The description of the configuration.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Required. The type of broker engine. Currently, Amazon MQ supports ACTIVEMQ and RABBITMQ.</p>
    pub fn engine_type(&self) -> ::std::option::Option<&crate::types::EngineType> {
        self.engine_type.as_ref()
    }
    /// <p>The broker engine version. Defaults to the latest available version for the specified broker engine type. For a list of supported engine versions, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p>
    pub fn engine_version(&self) -> ::std::option::Option<&str> {
        self.engine_version.as_deref()
    }
    /// <p>Required. The unique ID that Amazon MQ generates for the configuration.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>Required. The latest revision of the configuration.</p>
    pub fn latest_revision(&self) -> ::std::option::Option<&crate::types::ConfigurationRevision> {
        self.latest_revision.as_ref()
    }
    /// <p>Required. The name of the configuration. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The list of all tags associated with this configuration.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeConfigurationOutput`](crate::operation::describe_configuration::DescribeConfigurationOutput).
    pub fn builder() -> crate::operation::describe_configuration::builders::DescribeConfigurationOutputBuilder {
        crate::operation::describe_configuration::builders::DescribeConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DescribeConfigurationOutput`](crate::operation::describe_configuration::DescribeConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeConfigurationOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) authentication_strategy: ::std::option::Option<crate::types::AuthenticationStrategy>,
    pub(crate) created: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) engine_type: ::std::option::Option<crate::types::EngineType>,
    pub(crate) engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) latest_revision: ::std::option::Option<crate::types::ConfigurationRevision>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    _request_id: Option<String>,
}
impl DescribeConfigurationOutputBuilder {
    /// <p>Required. The ARN of the configuration.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required. The ARN of the configuration.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>Required. The ARN of the configuration.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>Optional. The authentication strategy associated with the configuration. The default is SIMPLE.</p>
    pub fn authentication_strategy(mut self, input: crate::types::AuthenticationStrategy) -> Self {
        self.authentication_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional. The authentication strategy associated with the configuration. The default is SIMPLE.</p>
    pub fn set_authentication_strategy(mut self, input: ::std::option::Option<crate::types::AuthenticationStrategy>) -> Self {
        self.authentication_strategy = input;
        self
    }
    /// <p>Optional. The authentication strategy associated with the configuration. The default is SIMPLE.</p>
    pub fn get_authentication_strategy(&self) -> &::std::option::Option<crate::types::AuthenticationStrategy> {
        &self.authentication_strategy
    }
    /// <p>Required. The date and time of the configuration revision.</p>
    pub fn created(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created = ::std::option::Option::Some(input);
        self
    }
    /// <p>Required. The date and time of the configuration revision.</p>
    pub fn set_created(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created = input;
        self
    }
    /// <p>Required. The date and time of the configuration revision.</p>
    pub fn get_created(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created
    }
    /// <p>Required. The description of the configuration.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required. The description of the configuration.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Required. The description of the configuration.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Required. The type of broker engine. Currently, Amazon MQ supports ACTIVEMQ and RABBITMQ.</p>
    pub fn engine_type(mut self, input: crate::types::EngineType) -> Self {
        self.engine_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Required. The type of broker engine. Currently, Amazon MQ supports ACTIVEMQ and RABBITMQ.</p>
    pub fn set_engine_type(mut self, input: ::std::option::Option<crate::types::EngineType>) -> Self {
        self.engine_type = input;
        self
    }
    /// <p>Required. The type of broker engine. Currently, Amazon MQ supports ACTIVEMQ and RABBITMQ.</p>
    pub fn get_engine_type(&self) -> &::std::option::Option<crate::types::EngineType> {
        &self.engine_type
    }
    /// <p>The broker engine version. Defaults to the latest available version for the specified broker engine type. For a list of supported engine versions, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p>
    pub fn engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The broker engine version. Defaults to the latest available version for the specified broker engine type. For a list of supported engine versions, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p>
    pub fn set_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine_version = input;
        self
    }
    /// <p>The broker engine version. Defaults to the latest available version for the specified broker engine type. For a list of supported engine versions, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p>
    pub fn get_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine_version
    }
    /// <p>Required. The unique ID that Amazon MQ generates for the configuration.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required. The unique ID that Amazon MQ generates for the configuration.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>Required. The unique ID that Amazon MQ generates for the configuration.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Required. The latest revision of the configuration.</p>
    pub fn latest_revision(mut self, input: crate::types::ConfigurationRevision) -> Self {
        self.latest_revision = ::std::option::Option::Some(input);
        self
    }
    /// <p>Required. The latest revision of the configuration.</p>
    pub fn set_latest_revision(mut self, input: ::std::option::Option<crate::types::ConfigurationRevision>) -> Self {
        self.latest_revision = input;
        self
    }
    /// <p>Required. The latest revision of the configuration.</p>
    pub fn get_latest_revision(&self) -> &::std::option::Option<crate::types::ConfigurationRevision> {
        &self.latest_revision
    }
    /// <p>Required. The name of the configuration. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Required. The name of the configuration. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Required. The name of the configuration. This value can contain only alphanumeric characters, dashes, periods, underscores, and tildes (- . _ ~). This value must be 1-150 characters long.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The list of all tags associated with this configuration.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The list of all tags associated with this configuration.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The list of all tags associated with this configuration.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeConfigurationOutput`](crate::operation::describe_configuration::DescribeConfigurationOutput).
    pub fn build(self) -> crate::operation::describe_configuration::DescribeConfigurationOutput {
        crate::operation::describe_configuration::DescribeConfigurationOutput {
            arn: self.arn,
            authentication_strategy: self.authentication_strategy,
            created: self.created,
            description: self.description,
            engine_type: self.engine_type,
            engine_version: self.engine_version,
            id: self.id,
            latest_revision: self.latest_revision,
            name: self.name,
            tags: self.tags,
            _request_id: self._request_id,
        }
    }
}
