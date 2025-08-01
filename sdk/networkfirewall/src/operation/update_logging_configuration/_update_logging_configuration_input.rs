// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLoggingConfigurationInput {
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub firewall_arn: ::std::option::Option<::std::string::String>,
    /// <p>The descriptive name of the firewall. You can't change the name of a firewall after you create it.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub firewall_name: ::std::option::Option<::std::string::String>,
    /// <p>Defines how Network Firewall performs logging for a firewall. If you omit this setting, Network Firewall disables logging for the firewall.</p>
    pub logging_configuration: ::std::option::Option<crate::types::LoggingConfiguration>,
    /// <p>A boolean that lets you enable or disable the detailed firewall monitoring dashboard on the firewall.</p>
    /// <p>The monitoring dashboard provides comprehensive visibility into your firewall's flow logs and alert logs. After you enable detailed monitoring, you can access these dashboards directly from the <b>Monitoring</b> page of the Network Firewall console.</p>
    /// <p>Specify <code>TRUE</code> to enable the the detailed monitoring dashboard on the firewall. Specify <code>FALSE</code> to disable the the detailed monitoring dashboard on the firewall.</p>
    pub enable_monitoring_dashboard: ::std::option::Option<bool>,
}
impl UpdateLoggingConfigurationInput {
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub fn firewall_arn(&self) -> ::std::option::Option<&str> {
        self.firewall_arn.as_deref()
    }
    /// <p>The descriptive name of the firewall. You can't change the name of a firewall after you create it.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub fn firewall_name(&self) -> ::std::option::Option<&str> {
        self.firewall_name.as_deref()
    }
    /// <p>Defines how Network Firewall performs logging for a firewall. If you omit this setting, Network Firewall disables logging for the firewall.</p>
    pub fn logging_configuration(&self) -> ::std::option::Option<&crate::types::LoggingConfiguration> {
        self.logging_configuration.as_ref()
    }
    /// <p>A boolean that lets you enable or disable the detailed firewall monitoring dashboard on the firewall.</p>
    /// <p>The monitoring dashboard provides comprehensive visibility into your firewall's flow logs and alert logs. After you enable detailed monitoring, you can access these dashboards directly from the <b>Monitoring</b> page of the Network Firewall console.</p>
    /// <p>Specify <code>TRUE</code> to enable the the detailed monitoring dashboard on the firewall. Specify <code>FALSE</code> to disable the the detailed monitoring dashboard on the firewall.</p>
    pub fn enable_monitoring_dashboard(&self) -> ::std::option::Option<bool> {
        self.enable_monitoring_dashboard
    }
}
impl UpdateLoggingConfigurationInput {
    /// Creates a new builder-style object to manufacture [`UpdateLoggingConfigurationInput`](crate::operation::update_logging_configuration::UpdateLoggingConfigurationInput).
    pub fn builder() -> crate::operation::update_logging_configuration::builders::UpdateLoggingConfigurationInputBuilder {
        crate::operation::update_logging_configuration::builders::UpdateLoggingConfigurationInputBuilder::default()
    }
}

/// A builder for [`UpdateLoggingConfigurationInput`](crate::operation::update_logging_configuration::UpdateLoggingConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLoggingConfigurationInputBuilder {
    pub(crate) firewall_arn: ::std::option::Option<::std::string::String>,
    pub(crate) firewall_name: ::std::option::Option<::std::string::String>,
    pub(crate) logging_configuration: ::std::option::Option<crate::types::LoggingConfiguration>,
    pub(crate) enable_monitoring_dashboard: ::std::option::Option<bool>,
}
impl UpdateLoggingConfigurationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub fn firewall_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.firewall_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub fn set_firewall_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.firewall_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the firewall.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub fn get_firewall_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.firewall_arn
    }
    /// <p>The descriptive name of the firewall. You can't change the name of a firewall after you create it.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub fn firewall_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.firewall_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The descriptive name of the firewall. You can't change the name of a firewall after you create it.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub fn set_firewall_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.firewall_name = input;
        self
    }
    /// <p>The descriptive name of the firewall. You can't change the name of a firewall after you create it.</p>
    /// <p>You must specify the ARN or the name, and you can specify both.</p>
    pub fn get_firewall_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.firewall_name
    }
    /// <p>Defines how Network Firewall performs logging for a firewall. If you omit this setting, Network Firewall disables logging for the firewall.</p>
    pub fn logging_configuration(mut self, input: crate::types::LoggingConfiguration) -> Self {
        self.logging_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines how Network Firewall performs logging for a firewall. If you omit this setting, Network Firewall disables logging for the firewall.</p>
    pub fn set_logging_configuration(mut self, input: ::std::option::Option<crate::types::LoggingConfiguration>) -> Self {
        self.logging_configuration = input;
        self
    }
    /// <p>Defines how Network Firewall performs logging for a firewall. If you omit this setting, Network Firewall disables logging for the firewall.</p>
    pub fn get_logging_configuration(&self) -> &::std::option::Option<crate::types::LoggingConfiguration> {
        &self.logging_configuration
    }
    /// <p>A boolean that lets you enable or disable the detailed firewall monitoring dashboard on the firewall.</p>
    /// <p>The monitoring dashboard provides comprehensive visibility into your firewall's flow logs and alert logs. After you enable detailed monitoring, you can access these dashboards directly from the <b>Monitoring</b> page of the Network Firewall console.</p>
    /// <p>Specify <code>TRUE</code> to enable the the detailed monitoring dashboard on the firewall. Specify <code>FALSE</code> to disable the the detailed monitoring dashboard on the firewall.</p>
    pub fn enable_monitoring_dashboard(mut self, input: bool) -> Self {
        self.enable_monitoring_dashboard = ::std::option::Option::Some(input);
        self
    }
    /// <p>A boolean that lets you enable or disable the detailed firewall monitoring dashboard on the firewall.</p>
    /// <p>The monitoring dashboard provides comprehensive visibility into your firewall's flow logs and alert logs. After you enable detailed monitoring, you can access these dashboards directly from the <b>Monitoring</b> page of the Network Firewall console.</p>
    /// <p>Specify <code>TRUE</code> to enable the the detailed monitoring dashboard on the firewall. Specify <code>FALSE</code> to disable the the detailed monitoring dashboard on the firewall.</p>
    pub fn set_enable_monitoring_dashboard(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_monitoring_dashboard = input;
        self
    }
    /// <p>A boolean that lets you enable or disable the detailed firewall monitoring dashboard on the firewall.</p>
    /// <p>The monitoring dashboard provides comprehensive visibility into your firewall's flow logs and alert logs. After you enable detailed monitoring, you can access these dashboards directly from the <b>Monitoring</b> page of the Network Firewall console.</p>
    /// <p>Specify <code>TRUE</code> to enable the the detailed monitoring dashboard on the firewall. Specify <code>FALSE</code> to disable the the detailed monitoring dashboard on the firewall.</p>
    pub fn get_enable_monitoring_dashboard(&self) -> &::std::option::Option<bool> {
        &self.enable_monitoring_dashboard
    }
    /// Consumes the builder and constructs a [`UpdateLoggingConfigurationInput`](crate::operation::update_logging_configuration::UpdateLoggingConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_logging_configuration::UpdateLoggingConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_logging_configuration::UpdateLoggingConfigurationInput {
            firewall_arn: self.firewall_arn,
            firewall_name: self.firewall_name,
            logging_configuration: self.logging_configuration,
            enable_monitoring_dashboard: self.enable_monitoring_dashboard,
        })
    }
}
