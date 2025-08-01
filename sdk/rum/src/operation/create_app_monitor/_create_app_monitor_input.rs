// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAppMonitorInput {
    /// <p>A name for the app monitor.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The top-level internet domain name for which your application has administrative authority.</p>
    pub domain: ::std::option::Option<::std::string::String>,
    /// <p>List the domain names for which your application has administrative authority. The <code>CreateAppMonitor</code> requires either the domain or the domain list.</p>
    pub domain_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Assigns one or more tags (key-value pairs) to the app monitor.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with an app monitor.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A structure that contains much of the configuration data for the app monitor. If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include <code>AppMonitorConfiguration</code>, you must set up your own authorization method. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html">Authorize your application to send data to Amazon Web Services</a>.</p>
    /// <p>If you omit this argument, the sample rate used for RUM is set to 10% of the user sessions.</p>
    pub app_monitor_configuration: ::std::option::Option<crate::types::AppMonitorConfiguration>,
    /// <p>Data collected by RUM is kept by RUM for 30 days and then deleted. This parameter specifies whether RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges.</p>
    /// <p>If you omit this parameter, the default is <code>false</code>.</p>
    pub cw_log_enabled: ::std::option::Option<bool>,
    /// <p>Specifies whether this app monitor allows the web client to define and send custom events. If you omit this parameter, custom events are <code>DISABLED</code>.</p>
    /// <p>For more information about custom events, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-custom-events.html">Send custom events</a>.</p>
    pub custom_events: ::std::option::Option<crate::types::CustomEvents>,
    /// <p>A structure that contains the configuration for how an app monitor can deobfuscate stack traces.</p>
    pub deobfuscation_configuration: ::std::option::Option<crate::types::DeobfuscationConfiguration>,
}
impl CreateAppMonitorInput {
    /// <p>A name for the app monitor.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The top-level internet domain name for which your application has administrative authority.</p>
    pub fn domain(&self) -> ::std::option::Option<&str> {
        self.domain.as_deref()
    }
    /// <p>List the domain names for which your application has administrative authority. The <code>CreateAppMonitor</code> requires either the domain or the domain list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.domain_list.is_none()`.
    pub fn domain_list(&self) -> &[::std::string::String] {
        self.domain_list.as_deref().unwrap_or_default()
    }
    /// <p>Assigns one or more tags (key-value pairs) to the app monitor.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with an app monitor.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>A structure that contains much of the configuration data for the app monitor. If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include <code>AppMonitorConfiguration</code>, you must set up your own authorization method. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html">Authorize your application to send data to Amazon Web Services</a>.</p>
    /// <p>If you omit this argument, the sample rate used for RUM is set to 10% of the user sessions.</p>
    pub fn app_monitor_configuration(&self) -> ::std::option::Option<&crate::types::AppMonitorConfiguration> {
        self.app_monitor_configuration.as_ref()
    }
    /// <p>Data collected by RUM is kept by RUM for 30 days and then deleted. This parameter specifies whether RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges.</p>
    /// <p>If you omit this parameter, the default is <code>false</code>.</p>
    pub fn cw_log_enabled(&self) -> ::std::option::Option<bool> {
        self.cw_log_enabled
    }
    /// <p>Specifies whether this app monitor allows the web client to define and send custom events. If you omit this parameter, custom events are <code>DISABLED</code>.</p>
    /// <p>For more information about custom events, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-custom-events.html">Send custom events</a>.</p>
    pub fn custom_events(&self) -> ::std::option::Option<&crate::types::CustomEvents> {
        self.custom_events.as_ref()
    }
    /// <p>A structure that contains the configuration for how an app monitor can deobfuscate stack traces.</p>
    pub fn deobfuscation_configuration(&self) -> ::std::option::Option<&crate::types::DeobfuscationConfiguration> {
        self.deobfuscation_configuration.as_ref()
    }
}
impl CreateAppMonitorInput {
    /// Creates a new builder-style object to manufacture [`CreateAppMonitorInput`](crate::operation::create_app_monitor::CreateAppMonitorInput).
    pub fn builder() -> crate::operation::create_app_monitor::builders::CreateAppMonitorInputBuilder {
        crate::operation::create_app_monitor::builders::CreateAppMonitorInputBuilder::default()
    }
}

/// A builder for [`CreateAppMonitorInput`](crate::operation::create_app_monitor::CreateAppMonitorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAppMonitorInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) domain: ::std::option::Option<::std::string::String>,
    pub(crate) domain_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) app_monitor_configuration: ::std::option::Option<crate::types::AppMonitorConfiguration>,
    pub(crate) cw_log_enabled: ::std::option::Option<bool>,
    pub(crate) custom_events: ::std::option::Option<crate::types::CustomEvents>,
    pub(crate) deobfuscation_configuration: ::std::option::Option<crate::types::DeobfuscationConfiguration>,
}
impl CreateAppMonitorInputBuilder {
    /// <p>A name for the app monitor.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the app monitor.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A name for the app monitor.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The top-level internet domain name for which your application has administrative authority.</p>
    pub fn domain(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The top-level internet domain name for which your application has administrative authority.</p>
    pub fn set_domain(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain = input;
        self
    }
    /// <p>The top-level internet domain name for which your application has administrative authority.</p>
    pub fn get_domain(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain
    }
    /// Appends an item to `domain_list`.
    ///
    /// To override the contents of this collection use [`set_domain_list`](Self::set_domain_list).
    ///
    /// <p>List the domain names for which your application has administrative authority. The <code>CreateAppMonitor</code> requires either the domain or the domain list.</p>
    pub fn domain_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.domain_list.unwrap_or_default();
        v.push(input.into());
        self.domain_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>List the domain names for which your application has administrative authority. The <code>CreateAppMonitor</code> requires either the domain or the domain list.</p>
    pub fn set_domain_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.domain_list = input;
        self
    }
    /// <p>List the domain names for which your application has administrative authority. The <code>CreateAppMonitor</code> requires either the domain or the domain list.</p>
    pub fn get_domain_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.domain_list
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Assigns one or more tags (key-value pairs) to the app monitor.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with an app monitor.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Assigns one or more tags (key-value pairs) to the app monitor.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with an app monitor.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Assigns one or more tags (key-value pairs) to the app monitor.</p>
    /// <p>Tags can help you organize and categorize your resources. You can also use them to scope user permissions by granting a user permission to access or change only resources with certain tag values.</p>
    /// <p>Tags don't have any semantic meaning to Amazon Web Services and are interpreted strictly as strings of characters.</p>
    /// <p>You can associate as many as 50 tags with an app monitor.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html">Tagging Amazon Web Services resources</a>.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>A structure that contains much of the configuration data for the app monitor. If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include <code>AppMonitorConfiguration</code>, you must set up your own authorization method. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html">Authorize your application to send data to Amazon Web Services</a>.</p>
    /// <p>If you omit this argument, the sample rate used for RUM is set to 10% of the user sessions.</p>
    pub fn app_monitor_configuration(mut self, input: crate::types::AppMonitorConfiguration) -> Self {
        self.app_monitor_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains much of the configuration data for the app monitor. If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include <code>AppMonitorConfiguration</code>, you must set up your own authorization method. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html">Authorize your application to send data to Amazon Web Services</a>.</p>
    /// <p>If you omit this argument, the sample rate used for RUM is set to 10% of the user sessions.</p>
    pub fn set_app_monitor_configuration(mut self, input: ::std::option::Option<crate::types::AppMonitorConfiguration>) -> Self {
        self.app_monitor_configuration = input;
        self
    }
    /// <p>A structure that contains much of the configuration data for the app monitor. If you are using Amazon Cognito for authorization, you must include this structure in your request, and it must include the ID of the Amazon Cognito identity pool to use for authorization. If you don't include <code>AppMonitorConfiguration</code>, you must set up your own authorization method. For more information, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-get-started-authorization.html">Authorize your application to send data to Amazon Web Services</a>.</p>
    /// <p>If you omit this argument, the sample rate used for RUM is set to 10% of the user sessions.</p>
    pub fn get_app_monitor_configuration(&self) -> &::std::option::Option<crate::types::AppMonitorConfiguration> {
        &self.app_monitor_configuration
    }
    /// <p>Data collected by RUM is kept by RUM for 30 days and then deleted. This parameter specifies whether RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges.</p>
    /// <p>If you omit this parameter, the default is <code>false</code>.</p>
    pub fn cw_log_enabled(mut self, input: bool) -> Self {
        self.cw_log_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Data collected by RUM is kept by RUM for 30 days and then deleted. This parameter specifies whether RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges.</p>
    /// <p>If you omit this parameter, the default is <code>false</code>.</p>
    pub fn set_cw_log_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.cw_log_enabled = input;
        self
    }
    /// <p>Data collected by RUM is kept by RUM for 30 days and then deleted. This parameter specifies whether RUM sends a copy of this telemetry data to Amazon CloudWatch Logs in your account. This enables you to keep the telemetry data for more than 30 days, but it does incur Amazon CloudWatch Logs charges.</p>
    /// <p>If you omit this parameter, the default is <code>false</code>.</p>
    pub fn get_cw_log_enabled(&self) -> &::std::option::Option<bool> {
        &self.cw_log_enabled
    }
    /// <p>Specifies whether this app monitor allows the web client to define and send custom events. If you omit this parameter, custom events are <code>DISABLED</code>.</p>
    /// <p>For more information about custom events, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-custom-events.html">Send custom events</a>.</p>
    pub fn custom_events(mut self, input: crate::types::CustomEvents) -> Self {
        self.custom_events = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether this app monitor allows the web client to define and send custom events. If you omit this parameter, custom events are <code>DISABLED</code>.</p>
    /// <p>For more information about custom events, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-custom-events.html">Send custom events</a>.</p>
    pub fn set_custom_events(mut self, input: ::std::option::Option<crate::types::CustomEvents>) -> Self {
        self.custom_events = input;
        self
    }
    /// <p>Specifies whether this app monitor allows the web client to define and send custom events. If you omit this parameter, custom events are <code>DISABLED</code>.</p>
    /// <p>For more information about custom events, see <a href="https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-RUM-custom-events.html">Send custom events</a>.</p>
    pub fn get_custom_events(&self) -> &::std::option::Option<crate::types::CustomEvents> {
        &self.custom_events
    }
    /// <p>A structure that contains the configuration for how an app monitor can deobfuscate stack traces.</p>
    pub fn deobfuscation_configuration(mut self, input: crate::types::DeobfuscationConfiguration) -> Self {
        self.deobfuscation_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains the configuration for how an app monitor can deobfuscate stack traces.</p>
    pub fn set_deobfuscation_configuration(mut self, input: ::std::option::Option<crate::types::DeobfuscationConfiguration>) -> Self {
        self.deobfuscation_configuration = input;
        self
    }
    /// <p>A structure that contains the configuration for how an app monitor can deobfuscate stack traces.</p>
    pub fn get_deobfuscation_configuration(&self) -> &::std::option::Option<crate::types::DeobfuscationConfiguration> {
        &self.deobfuscation_configuration
    }
    /// Consumes the builder and constructs a [`CreateAppMonitorInput`](crate::operation::create_app_monitor::CreateAppMonitorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_app_monitor::CreateAppMonitorInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_app_monitor::CreateAppMonitorInput {
            name: self.name,
            domain: self.domain,
            domain_list: self.domain_list,
            tags: self.tags,
            app_monitor_configuration: self.app_monitor_configuration,
            cw_log_enabled: self.cw_log_enabled,
            custom_events: self.custom_events,
            deobfuscation_configuration: self.deobfuscation_configuration,
        })
    }
}
