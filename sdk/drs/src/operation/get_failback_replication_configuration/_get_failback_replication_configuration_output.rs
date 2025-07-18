// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFailbackReplicationConfigurationOutput {
    /// <p>The ID of the Recovery Instance.</p>
    pub recovery_instance_id: ::std::string::String,
    /// <p>The name of the Failback Replication Configuration.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Configure bandwidth throttling for the outbound data transfer rate of the Recovery Instance in Mbps.</p>
    pub bandwidth_throttling: i64,
    /// <p>Whether to use Private IP for the failback replication of the Recovery Instance.</p>
    pub use_private_ip: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl GetFailbackReplicationConfigurationOutput {
    /// <p>The ID of the Recovery Instance.</p>
    pub fn recovery_instance_id(&self) -> &str {
        use std::ops::Deref;
        self.recovery_instance_id.deref()
    }
    /// <p>The name of the Failback Replication Configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Configure bandwidth throttling for the outbound data transfer rate of the Recovery Instance in Mbps.</p>
    pub fn bandwidth_throttling(&self) -> i64 {
        self.bandwidth_throttling
    }
    /// <p>Whether to use Private IP for the failback replication of the Recovery Instance.</p>
    pub fn use_private_ip(&self) -> ::std::option::Option<bool> {
        self.use_private_ip
    }
}
impl ::aws_types::request_id::RequestId for GetFailbackReplicationConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFailbackReplicationConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`GetFailbackReplicationConfigurationOutput`](crate::operation::get_failback_replication_configuration::GetFailbackReplicationConfigurationOutput).
    pub fn builder() -> crate::operation::get_failback_replication_configuration::builders::GetFailbackReplicationConfigurationOutputBuilder {
        crate::operation::get_failback_replication_configuration::builders::GetFailbackReplicationConfigurationOutputBuilder::default()
    }
}

/// A builder for [`GetFailbackReplicationConfigurationOutput`](crate::operation::get_failback_replication_configuration::GetFailbackReplicationConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFailbackReplicationConfigurationOutputBuilder {
    pub(crate) recovery_instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) bandwidth_throttling: ::std::option::Option<i64>,
    pub(crate) use_private_ip: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl GetFailbackReplicationConfigurationOutputBuilder {
    /// <p>The ID of the Recovery Instance.</p>
    /// This field is required.
    pub fn recovery_instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recovery_instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Recovery Instance.</p>
    pub fn set_recovery_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recovery_instance_id = input;
        self
    }
    /// <p>The ID of the Recovery Instance.</p>
    pub fn get_recovery_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recovery_instance_id
    }
    /// <p>The name of the Failback Replication Configuration.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Failback Replication Configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the Failback Replication Configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Configure bandwidth throttling for the outbound data transfer rate of the Recovery Instance in Mbps.</p>
    pub fn bandwidth_throttling(mut self, input: i64) -> Self {
        self.bandwidth_throttling = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configure bandwidth throttling for the outbound data transfer rate of the Recovery Instance in Mbps.</p>
    pub fn set_bandwidth_throttling(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bandwidth_throttling = input;
        self
    }
    /// <p>Configure bandwidth throttling for the outbound data transfer rate of the Recovery Instance in Mbps.</p>
    pub fn get_bandwidth_throttling(&self) -> &::std::option::Option<i64> {
        &self.bandwidth_throttling
    }
    /// <p>Whether to use Private IP for the failback replication of the Recovery Instance.</p>
    pub fn use_private_ip(mut self, input: bool) -> Self {
        self.use_private_ip = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to use Private IP for the failback replication of the Recovery Instance.</p>
    pub fn set_use_private_ip(mut self, input: ::std::option::Option<bool>) -> Self {
        self.use_private_ip = input;
        self
    }
    /// <p>Whether to use Private IP for the failback replication of the Recovery Instance.</p>
    pub fn get_use_private_ip(&self) -> &::std::option::Option<bool> {
        &self.use_private_ip
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFailbackReplicationConfigurationOutput`](crate::operation::get_failback_replication_configuration::GetFailbackReplicationConfigurationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`recovery_instance_id`](crate::operation::get_failback_replication_configuration::builders::GetFailbackReplicationConfigurationOutputBuilder::recovery_instance_id)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_failback_replication_configuration::GetFailbackReplicationConfigurationOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_failback_replication_configuration::GetFailbackReplicationConfigurationOutput {
                recovery_instance_id: self.recovery_instance_id.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "recovery_instance_id",
                        "recovery_instance_id was not specified but it is required when building GetFailbackReplicationConfigurationOutput",
                    )
                })?,
                name: self.name,
                bandwidth_throttling: self.bandwidth_throttling.unwrap_or_default(),
                use_private_ip: self.use_private_ip,
                _request_id: self._request_id,
            },
        )
    }
}
