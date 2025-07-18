// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The status of the firewall endpoint and firewall policy configuration for a single VPC subnet. This is part of the <code>FirewallStatus</code>.</p>
/// <p>For each VPC subnet that you associate with a firewall, Network Firewall does the following:</p>
/// <ul>
/// <li>
/// <p>Instantiates a firewall endpoint in the subnet, ready to take traffic.</p></li>
/// <li>
/// <p>Configures the endpoint with the current firewall policy settings, to provide the filtering behavior for the endpoint.</p></li>
/// </ul>
/// <p>When you update a firewall, for example to add a subnet association or change a rule group in the firewall policy, the affected sync states reflect out-of-sync or not ready status until the changes are complete.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SyncState {
    /// <p>The configuration and status for a single firewall subnet. For each configured subnet, Network Firewall creates the attachment by instantiating the firewall endpoint in the subnet so that it's ready to take traffic.</p>
    pub attachment: ::std::option::Option<crate::types::Attachment>,
    /// <p>The configuration status of the firewall endpoint in a single VPC subnet. Network Firewall provides each endpoint with the rules that are configured in the firewall policy. Each time you add a subnet or modify the associated firewall policy, Network Firewall synchronizes the rules in the endpoint, so it can properly filter network traffic.</p>
    pub config: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::PerObjectStatus>>,
}
impl SyncState {
    /// <p>The configuration and status for a single firewall subnet. For each configured subnet, Network Firewall creates the attachment by instantiating the firewall endpoint in the subnet so that it's ready to take traffic.</p>
    pub fn attachment(&self) -> ::std::option::Option<&crate::types::Attachment> {
        self.attachment.as_ref()
    }
    /// <p>The configuration status of the firewall endpoint in a single VPC subnet. Network Firewall provides each endpoint with the rules that are configured in the firewall policy. Each time you add a subnet or modify the associated firewall policy, Network Firewall synchronizes the rules in the endpoint, so it can properly filter network traffic.</p>
    pub fn config(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::PerObjectStatus>> {
        self.config.as_ref()
    }
}
impl SyncState {
    /// Creates a new builder-style object to manufacture [`SyncState`](crate::types::SyncState).
    pub fn builder() -> crate::types::builders::SyncStateBuilder {
        crate::types::builders::SyncStateBuilder::default()
    }
}

/// A builder for [`SyncState`](crate::types::SyncState).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SyncStateBuilder {
    pub(crate) attachment: ::std::option::Option<crate::types::Attachment>,
    pub(crate) config: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::PerObjectStatus>>,
}
impl SyncStateBuilder {
    /// <p>The configuration and status for a single firewall subnet. For each configured subnet, Network Firewall creates the attachment by instantiating the firewall endpoint in the subnet so that it's ready to take traffic.</p>
    pub fn attachment(mut self, input: crate::types::Attachment) -> Self {
        self.attachment = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration and status for a single firewall subnet. For each configured subnet, Network Firewall creates the attachment by instantiating the firewall endpoint in the subnet so that it's ready to take traffic.</p>
    pub fn set_attachment(mut self, input: ::std::option::Option<crate::types::Attachment>) -> Self {
        self.attachment = input;
        self
    }
    /// <p>The configuration and status for a single firewall subnet. For each configured subnet, Network Firewall creates the attachment by instantiating the firewall endpoint in the subnet so that it's ready to take traffic.</p>
    pub fn get_attachment(&self) -> &::std::option::Option<crate::types::Attachment> {
        &self.attachment
    }
    /// Adds a key-value pair to `config`.
    ///
    /// To override the contents of this collection use [`set_config`](Self::set_config).
    ///
    /// <p>The configuration status of the firewall endpoint in a single VPC subnet. Network Firewall provides each endpoint with the rules that are configured in the firewall policy. Each time you add a subnet or modify the associated firewall policy, Network Firewall synchronizes the rules in the endpoint, so it can properly filter network traffic.</p>
    pub fn config(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::PerObjectStatus) -> Self {
        let mut hash_map = self.config.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.config = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The configuration status of the firewall endpoint in a single VPC subnet. Network Firewall provides each endpoint with the rules that are configured in the firewall policy. Each time you add a subnet or modify the associated firewall policy, Network Firewall synchronizes the rules in the endpoint, so it can properly filter network traffic.</p>
    pub fn set_config(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::PerObjectStatus>>,
    ) -> Self {
        self.config = input;
        self
    }
    /// <p>The configuration status of the firewall endpoint in a single VPC subnet. Network Firewall provides each endpoint with the rules that are configured in the firewall policy. Each time you add a subnet or modify the associated firewall policy, Network Firewall synchronizes the rules in the endpoint, so it can properly filter network traffic.</p>
    pub fn get_config(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::PerObjectStatus>> {
        &self.config
    }
    /// Consumes the builder and constructs a [`SyncState`](crate::types::SyncState).
    pub fn build(self) -> crate::types::SyncState {
        crate::types::SyncState {
            attachment: self.attachment,
            config: self.config,
        }
    }
}
