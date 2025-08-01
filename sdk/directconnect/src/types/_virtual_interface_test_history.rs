// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the virtual interface failover test.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VirtualInterfaceTestHistory {
    /// <p>The ID of the virtual interface failover test.</p>
    pub test_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the tested virtual interface.</p>
    pub virtual_interface_id: ::std::option::Option<::std::string::String>,
    /// <p>The BGP peers that were put in the DOWN state as part of the virtual interface failover test.</p>
    pub bgp_peers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The status of the virtual interface failover test.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The owner ID of the tested virtual interface.</p>
    pub owner_account: ::std::option::Option<::std::string::String>,
    /// <p>The time that the virtual interface failover test ran in minutes.</p>
    pub test_duration_in_minutes: ::std::option::Option<i32>,
    /// <p>The time that the virtual interface moves to the DOWN state.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The time that the virtual interface moves out of the DOWN state.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl VirtualInterfaceTestHistory {
    /// <p>The ID of the virtual interface failover test.</p>
    pub fn test_id(&self) -> ::std::option::Option<&str> {
        self.test_id.as_deref()
    }
    /// <p>The ID of the tested virtual interface.</p>
    pub fn virtual_interface_id(&self) -> ::std::option::Option<&str> {
        self.virtual_interface_id.as_deref()
    }
    /// <p>The BGP peers that were put in the DOWN state as part of the virtual interface failover test.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.bgp_peers.is_none()`.
    pub fn bgp_peers(&self) -> &[::std::string::String] {
        self.bgp_peers.as_deref().unwrap_or_default()
    }
    /// <p>The status of the virtual interface failover test.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The owner ID of the tested virtual interface.</p>
    pub fn owner_account(&self) -> ::std::option::Option<&str> {
        self.owner_account.as_deref()
    }
    /// <p>The time that the virtual interface failover test ran in minutes.</p>
    pub fn test_duration_in_minutes(&self) -> ::std::option::Option<i32> {
        self.test_duration_in_minutes
    }
    /// <p>The time that the virtual interface moves to the DOWN state.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The time that the virtual interface moves out of the DOWN state.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
}
impl VirtualInterfaceTestHistory {
    /// Creates a new builder-style object to manufacture [`VirtualInterfaceTestHistory`](crate::types::VirtualInterfaceTestHistory).
    pub fn builder() -> crate::types::builders::VirtualInterfaceTestHistoryBuilder {
        crate::types::builders::VirtualInterfaceTestHistoryBuilder::default()
    }
}

/// A builder for [`VirtualInterfaceTestHistory`](crate::types::VirtualInterfaceTestHistory).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VirtualInterfaceTestHistoryBuilder {
    pub(crate) test_id: ::std::option::Option<::std::string::String>,
    pub(crate) virtual_interface_id: ::std::option::Option<::std::string::String>,
    pub(crate) bgp_peers: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) owner_account: ::std::option::Option<::std::string::String>,
    pub(crate) test_duration_in_minutes: ::std::option::Option<i32>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl VirtualInterfaceTestHistoryBuilder {
    /// <p>The ID of the virtual interface failover test.</p>
    pub fn test_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.test_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the virtual interface failover test.</p>
    pub fn set_test_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.test_id = input;
        self
    }
    /// <p>The ID of the virtual interface failover test.</p>
    pub fn get_test_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.test_id
    }
    /// <p>The ID of the tested virtual interface.</p>
    pub fn virtual_interface_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_interface_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the tested virtual interface.</p>
    pub fn set_virtual_interface_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_interface_id = input;
        self
    }
    /// <p>The ID of the tested virtual interface.</p>
    pub fn get_virtual_interface_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_interface_id
    }
    /// Appends an item to `bgp_peers`.
    ///
    /// To override the contents of this collection use [`set_bgp_peers`](Self::set_bgp_peers).
    ///
    /// <p>The BGP peers that were put in the DOWN state as part of the virtual interface failover test.</p>
    pub fn bgp_peers(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.bgp_peers.unwrap_or_default();
        v.push(input.into());
        self.bgp_peers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The BGP peers that were put in the DOWN state as part of the virtual interface failover test.</p>
    pub fn set_bgp_peers(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.bgp_peers = input;
        self
    }
    /// <p>The BGP peers that were put in the DOWN state as part of the virtual interface failover test.</p>
    pub fn get_bgp_peers(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.bgp_peers
    }
    /// <p>The status of the virtual interface failover test.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the virtual interface failover test.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the virtual interface failover test.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The owner ID of the tested virtual interface.</p>
    pub fn owner_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.owner_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner ID of the tested virtual interface.</p>
    pub fn set_owner_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.owner_account = input;
        self
    }
    /// <p>The owner ID of the tested virtual interface.</p>
    pub fn get_owner_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.owner_account
    }
    /// <p>The time that the virtual interface failover test ran in minutes.</p>
    pub fn test_duration_in_minutes(mut self, input: i32) -> Self {
        self.test_duration_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the virtual interface failover test ran in minutes.</p>
    pub fn set_test_duration_in_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.test_duration_in_minutes = input;
        self
    }
    /// <p>The time that the virtual interface failover test ran in minutes.</p>
    pub fn get_test_duration_in_minutes(&self) -> &::std::option::Option<i32> {
        &self.test_duration_in_minutes
    }
    /// <p>The time that the virtual interface moves to the DOWN state.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the virtual interface moves to the DOWN state.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The time that the virtual interface moves to the DOWN state.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The time that the virtual interface moves out of the DOWN state.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the virtual interface moves out of the DOWN state.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The time that the virtual interface moves out of the DOWN state.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// Consumes the builder and constructs a [`VirtualInterfaceTestHistory`](crate::types::VirtualInterfaceTestHistory).
    pub fn build(self) -> crate::types::VirtualInterfaceTestHistory {
        crate::types::VirtualInterfaceTestHistory {
            test_id: self.test_id,
            virtual_interface_id: self.virtual_interface_id,
            bgp_peers: self.bgp_peers,
            status: self.status,
            owner_account: self.owner_account,
            test_duration_in_minutes: self.test_duration_in_minutes,
            start_time: self.start_time,
            end_time: self.end_time,
        }
    }
}
