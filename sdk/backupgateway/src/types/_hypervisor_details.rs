// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>These are the details of the specified hypervisor. A hypervisor is hardware, software, or firmware that creates and manages virtual machines, and allocates resources to them.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct HypervisorDetails {
    /// <p>The server host of the hypervisor. This can be either an IP address or a fully-qualified domain name (FQDN).</p>
    pub host: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the hypervisor.</p>
    pub hypervisor_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the KMS used to encrypt the hypervisor.</p>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
    /// <p>This is the name of the specified hypervisor.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the group of gateways within the requested log.</p>
    pub log_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>This is the current state of the specified hypervisor.</p>
    /// <p>The possible states are <code>PENDING</code>, <code>ONLINE</code>, <code>OFFLINE</code>, or <code>ERROR</code>.</p>
    pub state: ::std::option::Option<crate::types::HypervisorState>,
    /// <p>This is the time when the most recent successful sync of metadata occurred.</p>
    pub last_successful_metadata_sync_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub latest_metadata_sync_status_message: ::std::option::Option<::std::string::String>,
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub latest_metadata_sync_status: ::std::option::Option<crate::types::SyncMetadataStatus>,
}
impl HypervisorDetails {
    /// <p>The server host of the hypervisor. This can be either an IP address or a fully-qualified domain name (FQDN).</p>
    pub fn host(&self) -> ::std::option::Option<&str> {
        self.host.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the hypervisor.</p>
    pub fn hypervisor_arn(&self) -> ::std::option::Option<&str> {
        self.hypervisor_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS used to encrypt the hypervisor.</p>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
    /// <p>This is the name of the specified hypervisor.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the group of gateways within the requested log.</p>
    pub fn log_group_arn(&self) -> ::std::option::Option<&str> {
        self.log_group_arn.as_deref()
    }
    /// <p>This is the current state of the specified hypervisor.</p>
    /// <p>The possible states are <code>PENDING</code>, <code>ONLINE</code>, <code>OFFLINE</code>, or <code>ERROR</code>.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::HypervisorState> {
        self.state.as_ref()
    }
    /// <p>This is the time when the most recent successful sync of metadata occurred.</p>
    pub fn last_successful_metadata_sync_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_successful_metadata_sync_time.as_ref()
    }
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub fn latest_metadata_sync_status_message(&self) -> ::std::option::Option<&str> {
        self.latest_metadata_sync_status_message.as_deref()
    }
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub fn latest_metadata_sync_status(&self) -> ::std::option::Option<&crate::types::SyncMetadataStatus> {
        self.latest_metadata_sync_status.as_ref()
    }
}
impl HypervisorDetails {
    /// Creates a new builder-style object to manufacture [`HypervisorDetails`](crate::types::HypervisorDetails).
    pub fn builder() -> crate::types::builders::HypervisorDetailsBuilder {
        crate::types::builders::HypervisorDetailsBuilder::default()
    }
}

/// A builder for [`HypervisorDetails`](crate::types::HypervisorDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct HypervisorDetailsBuilder {
    pub(crate) host: ::std::option::Option<::std::string::String>,
    pub(crate) hypervisor_arn: ::std::option::Option<::std::string::String>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) log_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::HypervisorState>,
    pub(crate) last_successful_metadata_sync_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) latest_metadata_sync_status_message: ::std::option::Option<::std::string::String>,
    pub(crate) latest_metadata_sync_status: ::std::option::Option<crate::types::SyncMetadataStatus>,
}
impl HypervisorDetailsBuilder {
    /// <p>The server host of the hypervisor. This can be either an IP address or a fully-qualified domain name (FQDN).</p>
    pub fn host(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.host = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The server host of the hypervisor. This can be either an IP address or a fully-qualified domain name (FQDN).</p>
    pub fn set_host(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.host = input;
        self
    }
    /// <p>The server host of the hypervisor. This can be either an IP address or a fully-qualified domain name (FQDN).</p>
    pub fn get_host(&self) -> &::std::option::Option<::std::string::String> {
        &self.host
    }
    /// <p>The Amazon Resource Name (ARN) of the hypervisor.</p>
    pub fn hypervisor_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hypervisor_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the hypervisor.</p>
    pub fn set_hypervisor_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hypervisor_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the hypervisor.</p>
    pub fn get_hypervisor_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.hypervisor_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS used to encrypt the hypervisor.</p>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS used to encrypt the hypervisor.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the KMS used to encrypt the hypervisor.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// <p>This is the name of the specified hypervisor.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This is the name of the specified hypervisor.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>This is the name of the specified hypervisor.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) of the group of gateways within the requested log.</p>
    pub fn log_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the group of gateways within the requested log.</p>
    pub fn set_log_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the group of gateways within the requested log.</p>
    pub fn get_log_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_arn
    }
    /// <p>This is the current state of the specified hypervisor.</p>
    /// <p>The possible states are <code>PENDING</code>, <code>ONLINE</code>, <code>OFFLINE</code>, or <code>ERROR</code>.</p>
    pub fn state(mut self, input: crate::types::HypervisorState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the current state of the specified hypervisor.</p>
    /// <p>The possible states are <code>PENDING</code>, <code>ONLINE</code>, <code>OFFLINE</code>, or <code>ERROR</code>.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::HypervisorState>) -> Self {
        self.state = input;
        self
    }
    /// <p>This is the current state of the specified hypervisor.</p>
    /// <p>The possible states are <code>PENDING</code>, <code>ONLINE</code>, <code>OFFLINE</code>, or <code>ERROR</code>.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::HypervisorState> {
        &self.state
    }
    /// <p>This is the time when the most recent successful sync of metadata occurred.</p>
    pub fn last_successful_metadata_sync_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_successful_metadata_sync_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the time when the most recent successful sync of metadata occurred.</p>
    pub fn set_last_successful_metadata_sync_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_successful_metadata_sync_time = input;
        self
    }
    /// <p>This is the time when the most recent successful sync of metadata occurred.</p>
    pub fn get_last_successful_metadata_sync_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_successful_metadata_sync_time
    }
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub fn latest_metadata_sync_status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.latest_metadata_sync_status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub fn set_latest_metadata_sync_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.latest_metadata_sync_status_message = input;
        self
    }
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub fn get_latest_metadata_sync_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.latest_metadata_sync_status_message
    }
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub fn latest_metadata_sync_status(mut self, input: crate::types::SyncMetadataStatus) -> Self {
        self.latest_metadata_sync_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub fn set_latest_metadata_sync_status(mut self, input: ::std::option::Option<crate::types::SyncMetadataStatus>) -> Self {
        self.latest_metadata_sync_status = input;
        self
    }
    /// <p>This is the most recent status for the indicated metadata sync.</p>
    pub fn get_latest_metadata_sync_status(&self) -> &::std::option::Option<crate::types::SyncMetadataStatus> {
        &self.latest_metadata_sync_status
    }
    /// Consumes the builder and constructs a [`HypervisorDetails`](crate::types::HypervisorDetails).
    pub fn build(self) -> crate::types::HypervisorDetails {
        crate::types::HypervisorDetails {
            host: self.host,
            hypervisor_arn: self.hypervisor_arn,
            kms_key_arn: self.kms_key_arn,
            name: self.name,
            log_group_arn: self.log_group_arn,
            state: self.state,
            last_successful_metadata_sync_time: self.last_successful_metadata_sync_time,
            latest_metadata_sync_status_message: self.latest_metadata_sync_status_message,
            latest_metadata_sync_status: self.latest_metadata_sync_status,
        }
    }
}
