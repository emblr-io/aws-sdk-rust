// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a private virtual interface to be provisioned on a connection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NewPrivateVirtualInterfaceAllocation {
    /// <p>The name of the virtual interface assigned by the customer network. The name has a maximum of 100 characters. The following are valid characters: a-z, 0-9 and a hyphen (-).</p>
    pub virtual_interface_name: ::std::string::String,
    /// <p>The ID of the VLAN.</p>
    pub vlan: i32,
    /// <p>The autonomous system (AS) number for Border Gateway Protocol (BGP) configuration.</p>
    /// <p>The valid values are 1-2147483647.</p>
    pub asn: i32,
    /// <p>The maximum transmission unit (MTU), in bytes. The supported values are 1500 and 8500. The default value is 1500.</p>
    pub mtu: ::std::option::Option<i32>,
    /// <p>The authentication key for BGP configuration. This string has a minimum length of 6 characters and and a maximun lenth of 80 characters.</p>
    pub auth_key: ::std::option::Option<::std::string::String>,
    /// <p>The IP address assigned to the Amazon interface.</p>
    pub amazon_address: ::std::option::Option<::std::string::String>,
    /// <p>The address family for the BGP peer.</p>
    pub address_family: ::std::option::Option<crate::types::AddressFamily>,
    /// <p>The IP address assigned to the customer interface.</p>
    pub customer_address: ::std::option::Option<::std::string::String>,
    /// <p>The tags associated with the private virtual interface.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl NewPrivateVirtualInterfaceAllocation {
    /// <p>The name of the virtual interface assigned by the customer network. The name has a maximum of 100 characters. The following are valid characters: a-z, 0-9 and a hyphen (-).</p>
    pub fn virtual_interface_name(&self) -> &str {
        use std::ops::Deref;
        self.virtual_interface_name.deref()
    }
    /// <p>The ID of the VLAN.</p>
    pub fn vlan(&self) -> i32 {
        self.vlan
    }
    /// <p>The autonomous system (AS) number for Border Gateway Protocol (BGP) configuration.</p>
    /// <p>The valid values are 1-2147483647.</p>
    pub fn asn(&self) -> i32 {
        self.asn
    }
    /// <p>The maximum transmission unit (MTU), in bytes. The supported values are 1500 and 8500. The default value is 1500.</p>
    pub fn mtu(&self) -> ::std::option::Option<i32> {
        self.mtu
    }
    /// <p>The authentication key for BGP configuration. This string has a minimum length of 6 characters and and a maximun lenth of 80 characters.</p>
    pub fn auth_key(&self) -> ::std::option::Option<&str> {
        self.auth_key.as_deref()
    }
    /// <p>The IP address assigned to the Amazon interface.</p>
    pub fn amazon_address(&self) -> ::std::option::Option<&str> {
        self.amazon_address.as_deref()
    }
    /// <p>The address family for the BGP peer.</p>
    pub fn address_family(&self) -> ::std::option::Option<&crate::types::AddressFamily> {
        self.address_family.as_ref()
    }
    /// <p>The IP address assigned to the customer interface.</p>
    pub fn customer_address(&self) -> ::std::option::Option<&str> {
        self.customer_address.as_deref()
    }
    /// <p>The tags associated with the private virtual interface.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl NewPrivateVirtualInterfaceAllocation {
    /// Creates a new builder-style object to manufacture [`NewPrivateVirtualInterfaceAllocation`](crate::types::NewPrivateVirtualInterfaceAllocation).
    pub fn builder() -> crate::types::builders::NewPrivateVirtualInterfaceAllocationBuilder {
        crate::types::builders::NewPrivateVirtualInterfaceAllocationBuilder::default()
    }
}

/// A builder for [`NewPrivateVirtualInterfaceAllocation`](crate::types::NewPrivateVirtualInterfaceAllocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NewPrivateVirtualInterfaceAllocationBuilder {
    pub(crate) virtual_interface_name: ::std::option::Option<::std::string::String>,
    pub(crate) vlan: ::std::option::Option<i32>,
    pub(crate) asn: ::std::option::Option<i32>,
    pub(crate) mtu: ::std::option::Option<i32>,
    pub(crate) auth_key: ::std::option::Option<::std::string::String>,
    pub(crate) amazon_address: ::std::option::Option<::std::string::String>,
    pub(crate) address_family: ::std::option::Option<crate::types::AddressFamily>,
    pub(crate) customer_address: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl NewPrivateVirtualInterfaceAllocationBuilder {
    /// <p>The name of the virtual interface assigned by the customer network. The name has a maximum of 100 characters. The following are valid characters: a-z, 0-9 and a hyphen (-).</p>
    /// This field is required.
    pub fn virtual_interface_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.virtual_interface_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the virtual interface assigned by the customer network. The name has a maximum of 100 characters. The following are valid characters: a-z, 0-9 and a hyphen (-).</p>
    pub fn set_virtual_interface_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.virtual_interface_name = input;
        self
    }
    /// <p>The name of the virtual interface assigned by the customer network. The name has a maximum of 100 characters. The following are valid characters: a-z, 0-9 and a hyphen (-).</p>
    pub fn get_virtual_interface_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.virtual_interface_name
    }
    /// <p>The ID of the VLAN.</p>
    /// This field is required.
    pub fn vlan(mut self, input: i32) -> Self {
        self.vlan = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ID of the VLAN.</p>
    pub fn set_vlan(mut self, input: ::std::option::Option<i32>) -> Self {
        self.vlan = input;
        self
    }
    /// <p>The ID of the VLAN.</p>
    pub fn get_vlan(&self) -> &::std::option::Option<i32> {
        &self.vlan
    }
    /// <p>The autonomous system (AS) number for Border Gateway Protocol (BGP) configuration.</p>
    /// <p>The valid values are 1-2147483647.</p>
    /// This field is required.
    pub fn asn(mut self, input: i32) -> Self {
        self.asn = ::std::option::Option::Some(input);
        self
    }
    /// <p>The autonomous system (AS) number for Border Gateway Protocol (BGP) configuration.</p>
    /// <p>The valid values are 1-2147483647.</p>
    pub fn set_asn(mut self, input: ::std::option::Option<i32>) -> Self {
        self.asn = input;
        self
    }
    /// <p>The autonomous system (AS) number for Border Gateway Protocol (BGP) configuration.</p>
    /// <p>The valid values are 1-2147483647.</p>
    pub fn get_asn(&self) -> &::std::option::Option<i32> {
        &self.asn
    }
    /// <p>The maximum transmission unit (MTU), in bytes. The supported values are 1500 and 8500. The default value is 1500.</p>
    pub fn mtu(mut self, input: i32) -> Self {
        self.mtu = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum transmission unit (MTU), in bytes. The supported values are 1500 and 8500. The default value is 1500.</p>
    pub fn set_mtu(mut self, input: ::std::option::Option<i32>) -> Self {
        self.mtu = input;
        self
    }
    /// <p>The maximum transmission unit (MTU), in bytes. The supported values are 1500 and 8500. The default value is 1500.</p>
    pub fn get_mtu(&self) -> &::std::option::Option<i32> {
        &self.mtu
    }
    /// <p>The authentication key for BGP configuration. This string has a minimum length of 6 characters and and a maximun lenth of 80 characters.</p>
    pub fn auth_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auth_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The authentication key for BGP configuration. This string has a minimum length of 6 characters and and a maximun lenth of 80 characters.</p>
    pub fn set_auth_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auth_key = input;
        self
    }
    /// <p>The authentication key for BGP configuration. This string has a minimum length of 6 characters and and a maximun lenth of 80 characters.</p>
    pub fn get_auth_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.auth_key
    }
    /// <p>The IP address assigned to the Amazon interface.</p>
    pub fn amazon_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.amazon_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IP address assigned to the Amazon interface.</p>
    pub fn set_amazon_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.amazon_address = input;
        self
    }
    /// <p>The IP address assigned to the Amazon interface.</p>
    pub fn get_amazon_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.amazon_address
    }
    /// <p>The address family for the BGP peer.</p>
    pub fn address_family(mut self, input: crate::types::AddressFamily) -> Self {
        self.address_family = ::std::option::Option::Some(input);
        self
    }
    /// <p>The address family for the BGP peer.</p>
    pub fn set_address_family(mut self, input: ::std::option::Option<crate::types::AddressFamily>) -> Self {
        self.address_family = input;
        self
    }
    /// <p>The address family for the BGP peer.</p>
    pub fn get_address_family(&self) -> &::std::option::Option<crate::types::AddressFamily> {
        &self.address_family
    }
    /// <p>The IP address assigned to the customer interface.</p>
    pub fn customer_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.customer_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IP address assigned to the customer interface.</p>
    pub fn set_customer_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.customer_address = input;
        self
    }
    /// <p>The IP address assigned to the customer interface.</p>
    pub fn get_customer_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.customer_address
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags associated with the private virtual interface.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags associated with the private virtual interface.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags associated with the private virtual interface.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`NewPrivateVirtualInterfaceAllocation`](crate::types::NewPrivateVirtualInterfaceAllocation).
    /// This method will fail if any of the following fields are not set:
    /// - [`virtual_interface_name`](crate::types::builders::NewPrivateVirtualInterfaceAllocationBuilder::virtual_interface_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::NewPrivateVirtualInterfaceAllocation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::NewPrivateVirtualInterfaceAllocation {
            virtual_interface_name: self.virtual_interface_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "virtual_interface_name",
                    "virtual_interface_name was not specified but it is required when building NewPrivateVirtualInterfaceAllocation",
                )
            })?,
            vlan: self.vlan.unwrap_or_default(),
            asn: self.asn.unwrap_or_default(),
            mtu: self.mtu,
            auth_key: self.auth_key,
            amazon_address: self.amazon_address,
            address_family: self.address_family,
            customer_address: self.customer_address,
            tags: self.tags,
        })
    }
}
