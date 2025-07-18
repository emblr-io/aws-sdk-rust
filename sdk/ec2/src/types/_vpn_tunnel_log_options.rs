// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Options for logging VPN tunnel activity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VpnTunnelLogOptions {
    /// <p>Options for sending VPN tunnel logs to CloudWatch.</p>
    pub cloud_watch_log_options: ::std::option::Option<crate::types::CloudWatchLogOptions>,
}
impl VpnTunnelLogOptions {
    /// <p>Options for sending VPN tunnel logs to CloudWatch.</p>
    pub fn cloud_watch_log_options(&self) -> ::std::option::Option<&crate::types::CloudWatchLogOptions> {
        self.cloud_watch_log_options.as_ref()
    }
}
impl VpnTunnelLogOptions {
    /// Creates a new builder-style object to manufacture [`VpnTunnelLogOptions`](crate::types::VpnTunnelLogOptions).
    pub fn builder() -> crate::types::builders::VpnTunnelLogOptionsBuilder {
        crate::types::builders::VpnTunnelLogOptionsBuilder::default()
    }
}

/// A builder for [`VpnTunnelLogOptions`](crate::types::VpnTunnelLogOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VpnTunnelLogOptionsBuilder {
    pub(crate) cloud_watch_log_options: ::std::option::Option<crate::types::CloudWatchLogOptions>,
}
impl VpnTunnelLogOptionsBuilder {
    /// <p>Options for sending VPN tunnel logs to CloudWatch.</p>
    pub fn cloud_watch_log_options(mut self, input: crate::types::CloudWatchLogOptions) -> Self {
        self.cloud_watch_log_options = ::std::option::Option::Some(input);
        self
    }
    /// <p>Options for sending VPN tunnel logs to CloudWatch.</p>
    pub fn set_cloud_watch_log_options(mut self, input: ::std::option::Option<crate::types::CloudWatchLogOptions>) -> Self {
        self.cloud_watch_log_options = input;
        self
    }
    /// <p>Options for sending VPN tunnel logs to CloudWatch.</p>
    pub fn get_cloud_watch_log_options(&self) -> &::std::option::Option<crate::types::CloudWatchLogOptions> {
        &self.cloud_watch_log_options
    }
    /// Consumes the builder and constructs a [`VpnTunnelLogOptions`](crate::types::VpnTunnelLogOptions).
    pub fn build(self) -> crate::types::VpnTunnelLogOptions {
        crate::types::VpnTunnelLogOptions {
            cloud_watch_log_options: self.cloud_watch_log_options,
        }
    }
}
