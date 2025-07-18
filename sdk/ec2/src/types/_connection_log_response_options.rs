// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the client connection logging options for a Client VPN endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConnectionLogResponseOptions {
    /// <p>Indicates whether client connection logging is enabled for the Client VPN endpoint.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>The name of the Amazon CloudWatch Logs log group to which connection logging data is published.</p>
    pub cloudwatch_log_group: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Amazon CloudWatch Logs log stream to which connection logging data is published.</p>
    pub cloudwatch_log_stream: ::std::option::Option<::std::string::String>,
}
impl ConnectionLogResponseOptions {
    /// <p>Indicates whether client connection logging is enabled for the Client VPN endpoint.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>The name of the Amazon CloudWatch Logs log group to which connection logging data is published.</p>
    pub fn cloudwatch_log_group(&self) -> ::std::option::Option<&str> {
        self.cloudwatch_log_group.as_deref()
    }
    /// <p>The name of the Amazon CloudWatch Logs log stream to which connection logging data is published.</p>
    pub fn cloudwatch_log_stream(&self) -> ::std::option::Option<&str> {
        self.cloudwatch_log_stream.as_deref()
    }
}
impl ConnectionLogResponseOptions {
    /// Creates a new builder-style object to manufacture [`ConnectionLogResponseOptions`](crate::types::ConnectionLogResponseOptions).
    pub fn builder() -> crate::types::builders::ConnectionLogResponseOptionsBuilder {
        crate::types::builders::ConnectionLogResponseOptionsBuilder::default()
    }
}

/// A builder for [`ConnectionLogResponseOptions`](crate::types::ConnectionLogResponseOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConnectionLogResponseOptionsBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) cloudwatch_log_group: ::std::option::Option<::std::string::String>,
    pub(crate) cloudwatch_log_stream: ::std::option::Option<::std::string::String>,
}
impl ConnectionLogResponseOptionsBuilder {
    /// <p>Indicates whether client connection logging is enabled for the Client VPN endpoint.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether client connection logging is enabled for the Client VPN endpoint.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>Indicates whether client connection logging is enabled for the Client VPN endpoint.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>The name of the Amazon CloudWatch Logs log group to which connection logging data is published.</p>
    pub fn cloudwatch_log_group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cloudwatch_log_group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon CloudWatch Logs log group to which connection logging data is published.</p>
    pub fn set_cloudwatch_log_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cloudwatch_log_group = input;
        self
    }
    /// <p>The name of the Amazon CloudWatch Logs log group to which connection logging data is published.</p>
    pub fn get_cloudwatch_log_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.cloudwatch_log_group
    }
    /// <p>The name of the Amazon CloudWatch Logs log stream to which connection logging data is published.</p>
    pub fn cloudwatch_log_stream(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cloudwatch_log_stream = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon CloudWatch Logs log stream to which connection logging data is published.</p>
    pub fn set_cloudwatch_log_stream(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cloudwatch_log_stream = input;
        self
    }
    /// <p>The name of the Amazon CloudWatch Logs log stream to which connection logging data is published.</p>
    pub fn get_cloudwatch_log_stream(&self) -> &::std::option::Option<::std::string::String> {
        &self.cloudwatch_log_stream
    }
    /// Consumes the builder and constructs a [`ConnectionLogResponseOptions`](crate::types::ConnectionLogResponseOptions).
    pub fn build(self) -> crate::types::ConnectionLogResponseOptions {
        crate::types::ConnectionLogResponseOptions {
            enabled: self.enabled,
            cloudwatch_log_group: self.cloudwatch_log_group,
            cloudwatch_log_stream: self.cloudwatch_log_stream,
        }
    }
}
