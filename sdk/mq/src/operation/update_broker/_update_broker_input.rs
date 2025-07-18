// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Updates the broker using the specified properties.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateBrokerInput {
    /// <p>Optional. The authentication strategy used to secure the broker. The default is SIMPLE.</p>
    pub authentication_strategy: ::std::option::Option<crate::types::AuthenticationStrategy>,
    /// <p>Enables automatic upgrades to new patch versions for brokers as new versions are released and supported by Amazon MQ. Automatic upgrades occur during the scheduled maintenance window or after a manual broker reboot.</p><note>
    /// <p>Must be set to true for ActiveMQ brokers version 5.18 and above and for RabbitMQ brokers version 3.13 and above.</p>
    /// </note>
    pub auto_minor_version_upgrade: ::std::option::Option<bool>,
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub broker_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of information about the configuration.</p>
    pub configuration: ::std::option::Option<crate::types::ConfigurationId>,
    /// <p>The broker engine version. For more information, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p><note>
    /// <p>When upgrading to ActiveMQ version 5.18 and above or RabbitMQ version 3.13 and above, you must have autoMinorVersionUpgrade set to true for the broker.</p>
    /// </note>
    pub engine_version: ::std::option::Option<::std::string::String>,
    /// <p>The broker's host instance type to upgrade to. For a list of supported instance types, see <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/broker.html#broker-instance-types">Broker instance types</a>.</p>
    pub host_instance_type: ::std::option::Option<::std::string::String>,
    /// <p>Optional. The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.</p>
    pub ldap_server_metadata: ::std::option::Option<crate::types::LdapServerMetadataInput>,
    /// <p>Enables Amazon CloudWatch logging for brokers.</p>
    pub logs: ::std::option::Option<crate::types::Logs>,
    /// <p>The parameters that determine the WeeklyStartTime.</p>
    pub maintenance_window_start_time: ::std::option::Option<crate::types::WeeklyStartTime>,
    /// <p>The list of security groups (1 minimum, 5 maximum) that authorizes connections to brokers.</p>
    pub security_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Defines whether this broker is a part of a data replication pair.</p>
    pub data_replication_mode: ::std::option::Option<crate::types::DataReplicationMode>,
}
impl UpdateBrokerInput {
    /// <p>Optional. The authentication strategy used to secure the broker. The default is SIMPLE.</p>
    pub fn authentication_strategy(&self) -> ::std::option::Option<&crate::types::AuthenticationStrategy> {
        self.authentication_strategy.as_ref()
    }
    /// <p>Enables automatic upgrades to new patch versions for brokers as new versions are released and supported by Amazon MQ. Automatic upgrades occur during the scheduled maintenance window or after a manual broker reboot.</p><note>
    /// <p>Must be set to true for ActiveMQ brokers version 5.18 and above and for RabbitMQ brokers version 3.13 and above.</p>
    /// </note>
    pub fn auto_minor_version_upgrade(&self) -> ::std::option::Option<bool> {
        self.auto_minor_version_upgrade
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn broker_id(&self) -> ::std::option::Option<&str> {
        self.broker_id.as_deref()
    }
    /// <p>A list of information about the configuration.</p>
    pub fn configuration(&self) -> ::std::option::Option<&crate::types::ConfigurationId> {
        self.configuration.as_ref()
    }
    /// <p>The broker engine version. For more information, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p><note>
    /// <p>When upgrading to ActiveMQ version 5.18 and above or RabbitMQ version 3.13 and above, you must have autoMinorVersionUpgrade set to true for the broker.</p>
    /// </note>
    pub fn engine_version(&self) -> ::std::option::Option<&str> {
        self.engine_version.as_deref()
    }
    /// <p>The broker's host instance type to upgrade to. For a list of supported instance types, see <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/broker.html#broker-instance-types">Broker instance types</a>.</p>
    pub fn host_instance_type(&self) -> ::std::option::Option<&str> {
        self.host_instance_type.as_deref()
    }
    /// <p>Optional. The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.</p>
    pub fn ldap_server_metadata(&self) -> ::std::option::Option<&crate::types::LdapServerMetadataInput> {
        self.ldap_server_metadata.as_ref()
    }
    /// <p>Enables Amazon CloudWatch logging for brokers.</p>
    pub fn logs(&self) -> ::std::option::Option<&crate::types::Logs> {
        self.logs.as_ref()
    }
    /// <p>The parameters that determine the WeeklyStartTime.</p>
    pub fn maintenance_window_start_time(&self) -> ::std::option::Option<&crate::types::WeeklyStartTime> {
        self.maintenance_window_start_time.as_ref()
    }
    /// <p>The list of security groups (1 minimum, 5 maximum) that authorizes connections to brokers.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_groups.is_none()`.
    pub fn security_groups(&self) -> &[::std::string::String] {
        self.security_groups.as_deref().unwrap_or_default()
    }
    /// <p>Defines whether this broker is a part of a data replication pair.</p>
    pub fn data_replication_mode(&self) -> ::std::option::Option<&crate::types::DataReplicationMode> {
        self.data_replication_mode.as_ref()
    }
}
impl UpdateBrokerInput {
    /// Creates a new builder-style object to manufacture [`UpdateBrokerInput`](crate::operation::update_broker::UpdateBrokerInput).
    pub fn builder() -> crate::operation::update_broker::builders::UpdateBrokerInputBuilder {
        crate::operation::update_broker::builders::UpdateBrokerInputBuilder::default()
    }
}

/// A builder for [`UpdateBrokerInput`](crate::operation::update_broker::UpdateBrokerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateBrokerInputBuilder {
    pub(crate) authentication_strategy: ::std::option::Option<crate::types::AuthenticationStrategy>,
    pub(crate) auto_minor_version_upgrade: ::std::option::Option<bool>,
    pub(crate) broker_id: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<crate::types::ConfigurationId>,
    pub(crate) engine_version: ::std::option::Option<::std::string::String>,
    pub(crate) host_instance_type: ::std::option::Option<::std::string::String>,
    pub(crate) ldap_server_metadata: ::std::option::Option<crate::types::LdapServerMetadataInput>,
    pub(crate) logs: ::std::option::Option<crate::types::Logs>,
    pub(crate) maintenance_window_start_time: ::std::option::Option<crate::types::WeeklyStartTime>,
    pub(crate) security_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) data_replication_mode: ::std::option::Option<crate::types::DataReplicationMode>,
}
impl UpdateBrokerInputBuilder {
    /// <p>Optional. The authentication strategy used to secure the broker. The default is SIMPLE.</p>
    pub fn authentication_strategy(mut self, input: crate::types::AuthenticationStrategy) -> Self {
        self.authentication_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional. The authentication strategy used to secure the broker. The default is SIMPLE.</p>
    pub fn set_authentication_strategy(mut self, input: ::std::option::Option<crate::types::AuthenticationStrategy>) -> Self {
        self.authentication_strategy = input;
        self
    }
    /// <p>Optional. The authentication strategy used to secure the broker. The default is SIMPLE.</p>
    pub fn get_authentication_strategy(&self) -> &::std::option::Option<crate::types::AuthenticationStrategy> {
        &self.authentication_strategy
    }
    /// <p>Enables automatic upgrades to new patch versions for brokers as new versions are released and supported by Amazon MQ. Automatic upgrades occur during the scheduled maintenance window or after a manual broker reboot.</p><note>
    /// <p>Must be set to true for ActiveMQ brokers version 5.18 and above and for RabbitMQ brokers version 3.13 and above.</p>
    /// </note>
    pub fn auto_minor_version_upgrade(mut self, input: bool) -> Self {
        self.auto_minor_version_upgrade = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables automatic upgrades to new patch versions for brokers as new versions are released and supported by Amazon MQ. Automatic upgrades occur during the scheduled maintenance window or after a manual broker reboot.</p><note>
    /// <p>Must be set to true for ActiveMQ brokers version 5.18 and above and for RabbitMQ brokers version 3.13 and above.</p>
    /// </note>
    pub fn set_auto_minor_version_upgrade(mut self, input: ::std::option::Option<bool>) -> Self {
        self.auto_minor_version_upgrade = input;
        self
    }
    /// <p>Enables automatic upgrades to new patch versions for brokers as new versions are released and supported by Amazon MQ. Automatic upgrades occur during the scheduled maintenance window or after a manual broker reboot.</p><note>
    /// <p>Must be set to true for ActiveMQ brokers version 5.18 and above and for RabbitMQ brokers version 3.13 and above.</p>
    /// </note>
    pub fn get_auto_minor_version_upgrade(&self) -> &::std::option::Option<bool> {
        &self.auto_minor_version_upgrade
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    /// This field is required.
    pub fn broker_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.broker_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn set_broker_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.broker_id = input;
        self
    }
    /// <p>The unique ID that Amazon MQ generates for the broker.</p>
    pub fn get_broker_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.broker_id
    }
    /// <p>A list of information about the configuration.</p>
    pub fn configuration(mut self, input: crate::types::ConfigurationId) -> Self {
        self.configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A list of information about the configuration.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<crate::types::ConfigurationId>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>A list of information about the configuration.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<crate::types::ConfigurationId> {
        &self.configuration
    }
    /// <p>The broker engine version. For more information, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p><note>
    /// <p>When upgrading to ActiveMQ version 5.18 and above or RabbitMQ version 3.13 and above, you must have autoMinorVersionUpgrade set to true for the broker.</p>
    /// </note>
    pub fn engine_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.engine_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The broker engine version. For more information, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p><note>
    /// <p>When upgrading to ActiveMQ version 5.18 and above or RabbitMQ version 3.13 and above, you must have autoMinorVersionUpgrade set to true for the broker.</p>
    /// </note>
    pub fn set_engine_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.engine_version = input;
        self
    }
    /// <p>The broker engine version. For more information, see the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/activemq-version-management.html">ActiveMQ version management</a> and the <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/rabbitmq-version-management.html">RabbitMQ version management</a> sections in the Amazon MQ Developer Guide.</p><note>
    /// <p>When upgrading to ActiveMQ version 5.18 and above or RabbitMQ version 3.13 and above, you must have autoMinorVersionUpgrade set to true for the broker.</p>
    /// </note>
    pub fn get_engine_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.engine_version
    }
    /// <p>The broker's host instance type to upgrade to. For a list of supported instance types, see <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/broker.html#broker-instance-types">Broker instance types</a>.</p>
    pub fn host_instance_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.host_instance_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The broker's host instance type to upgrade to. For a list of supported instance types, see <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/broker.html#broker-instance-types">Broker instance types</a>.</p>
    pub fn set_host_instance_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.host_instance_type = input;
        self
    }
    /// <p>The broker's host instance type to upgrade to. For a list of supported instance types, see <a href="https://docs.aws.amazon.com//amazon-mq/latest/developer-guide/broker.html#broker-instance-types">Broker instance types</a>.</p>
    pub fn get_host_instance_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.host_instance_type
    }
    /// <p>Optional. The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.</p>
    pub fn ldap_server_metadata(mut self, input: crate::types::LdapServerMetadataInput) -> Self {
        self.ldap_server_metadata = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional. The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.</p>
    pub fn set_ldap_server_metadata(mut self, input: ::std::option::Option<crate::types::LdapServerMetadataInput>) -> Self {
        self.ldap_server_metadata = input;
        self
    }
    /// <p>Optional. The metadata of the LDAP server used to authenticate and authorize connections to the broker. Does not apply to RabbitMQ brokers.</p>
    pub fn get_ldap_server_metadata(&self) -> &::std::option::Option<crate::types::LdapServerMetadataInput> {
        &self.ldap_server_metadata
    }
    /// <p>Enables Amazon CloudWatch logging for brokers.</p>
    pub fn logs(mut self, input: crate::types::Logs) -> Self {
        self.logs = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables Amazon CloudWatch logging for brokers.</p>
    pub fn set_logs(mut self, input: ::std::option::Option<crate::types::Logs>) -> Self {
        self.logs = input;
        self
    }
    /// <p>Enables Amazon CloudWatch logging for brokers.</p>
    pub fn get_logs(&self) -> &::std::option::Option<crate::types::Logs> {
        &self.logs
    }
    /// <p>The parameters that determine the WeeklyStartTime.</p>
    pub fn maintenance_window_start_time(mut self, input: crate::types::WeeklyStartTime) -> Self {
        self.maintenance_window_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The parameters that determine the WeeklyStartTime.</p>
    pub fn set_maintenance_window_start_time(mut self, input: ::std::option::Option<crate::types::WeeklyStartTime>) -> Self {
        self.maintenance_window_start_time = input;
        self
    }
    /// <p>The parameters that determine the WeeklyStartTime.</p>
    pub fn get_maintenance_window_start_time(&self) -> &::std::option::Option<crate::types::WeeklyStartTime> {
        &self.maintenance_window_start_time
    }
    /// Appends an item to `security_groups`.
    ///
    /// To override the contents of this collection use [`set_security_groups`](Self::set_security_groups).
    ///
    /// <p>The list of security groups (1 minimum, 5 maximum) that authorizes connections to brokers.</p>
    pub fn security_groups(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_groups.unwrap_or_default();
        v.push(input.into());
        self.security_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of security groups (1 minimum, 5 maximum) that authorizes connections to brokers.</p>
    pub fn set_security_groups(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_groups = input;
        self
    }
    /// <p>The list of security groups (1 minimum, 5 maximum) that authorizes connections to brokers.</p>
    pub fn get_security_groups(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_groups
    }
    /// <p>Defines whether this broker is a part of a data replication pair.</p>
    pub fn data_replication_mode(mut self, input: crate::types::DataReplicationMode) -> Self {
        self.data_replication_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines whether this broker is a part of a data replication pair.</p>
    pub fn set_data_replication_mode(mut self, input: ::std::option::Option<crate::types::DataReplicationMode>) -> Self {
        self.data_replication_mode = input;
        self
    }
    /// <p>Defines whether this broker is a part of a data replication pair.</p>
    pub fn get_data_replication_mode(&self) -> &::std::option::Option<crate::types::DataReplicationMode> {
        &self.data_replication_mode
    }
    /// Consumes the builder and constructs a [`UpdateBrokerInput`](crate::operation::update_broker::UpdateBrokerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_broker::UpdateBrokerInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_broker::UpdateBrokerInput {
            authentication_strategy: self.authentication_strategy,
            auto_minor_version_upgrade: self.auto_minor_version_upgrade,
            broker_id: self.broker_id,
            configuration: self.configuration,
            engine_version: self.engine_version,
            host_instance_type: self.host_instance_type,
            ldap_server_metadata: self.ldap_server_metadata,
            logs: self.logs,
            maintenance_window_start_time: self.maintenance_window_start_time,
            security_groups: self.security_groups,
            data_replication_mode: self.data_replication_mode,
        })
    }
}
