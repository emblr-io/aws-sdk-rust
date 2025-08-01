// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration details about the network where the Privatelink endpoint of the cluster resides.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VpcConfiguration {
    /// <p>The identifier of the VPC endpoint.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the VPC security group applied to the VPC endpoint ENI for the cluster.</p>
    pub security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The identifier of the subnet that the Privatelink VPC endpoint uses to connect to the cluster.</p>
    pub subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The IP address type for cluster network configuration parameters. The following type is available:</p>
    /// <ul>
    /// <li>
    /// <p>IP_V4 – IP address version 4</p></li>
    /// </ul>
    pub ip_address_type: ::std::option::Option<crate::types::IpAddressType>,
}
impl VpcConfiguration {
    /// <p>The identifier of the VPC endpoint.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>The unique identifier of the VPC security group applied to the VPC endpoint ENI for the cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_ids.is_none()`.
    pub fn security_group_ids(&self) -> &[::std::string::String] {
        self.security_group_ids.as_deref().unwrap_or_default()
    }
    /// <p>The identifier of the subnet that the Privatelink VPC endpoint uses to connect to the cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ids.is_none()`.
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        self.subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The IP address type for cluster network configuration parameters. The following type is available:</p>
    /// <ul>
    /// <li>
    /// <p>IP_V4 – IP address version 4</p></li>
    /// </ul>
    pub fn ip_address_type(&self) -> ::std::option::Option<&crate::types::IpAddressType> {
        self.ip_address_type.as_ref()
    }
}
impl VpcConfiguration {
    /// Creates a new builder-style object to manufacture [`VpcConfiguration`](crate::types::VpcConfiguration).
    pub fn builder() -> crate::types::builders::VpcConfigurationBuilder {
        crate::types::builders::VpcConfigurationBuilder::default()
    }
}

/// A builder for [`VpcConfiguration`](crate::types::VpcConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VpcConfigurationBuilder {
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) ip_address_type: ::std::option::Option<crate::types::IpAddressType>,
}
impl VpcConfigurationBuilder {
    /// <p>The identifier of the VPC endpoint.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the VPC endpoint.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The identifier of the VPC endpoint.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// Appends an item to `security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_security_group_ids`](Self::set_security_group_ids).
    ///
    /// <p>The unique identifier of the VPC security group applied to the VPC endpoint ENI for the cluster.</p>
    pub fn security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The unique identifier of the VPC security group applied to the VPC endpoint ENI for the cluster.</p>
    pub fn set_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_ids = input;
        self
    }
    /// <p>The unique identifier of the VPC security group applied to the VPC endpoint ENI for the cluster.</p>
    pub fn get_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_ids
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>The identifier of the subnet that the Privatelink VPC endpoint uses to connect to the cluster.</p>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The identifier of the subnet that the Privatelink VPC endpoint uses to connect to the cluster.</p>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>The identifier of the subnet that the Privatelink VPC endpoint uses to connect to the cluster.</p>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// <p>The IP address type for cluster network configuration parameters. The following type is available:</p>
    /// <ul>
    /// <li>
    /// <p>IP_V4 – IP address version 4</p></li>
    /// </ul>
    pub fn ip_address_type(mut self, input: crate::types::IpAddressType) -> Self {
        self.ip_address_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The IP address type for cluster network configuration parameters. The following type is available:</p>
    /// <ul>
    /// <li>
    /// <p>IP_V4 – IP address version 4</p></li>
    /// </ul>
    pub fn set_ip_address_type(mut self, input: ::std::option::Option<crate::types::IpAddressType>) -> Self {
        self.ip_address_type = input;
        self
    }
    /// <p>The IP address type for cluster network configuration parameters. The following type is available:</p>
    /// <ul>
    /// <li>
    /// <p>IP_V4 – IP address version 4</p></li>
    /// </ul>
    pub fn get_ip_address_type(&self) -> &::std::option::Option<crate::types::IpAddressType> {
        &self.ip_address_type
    }
    /// Consumes the builder and constructs a [`VpcConfiguration`](crate::types::VpcConfiguration).
    pub fn build(self) -> crate::types::VpcConfiguration {
        crate::types::VpcConfiguration {
            vpc_id: self.vpc_id,
            security_group_ids: self.security_group_ids,
            subnet_ids: self.subnet_ids,
            ip_address_type: self.ip_address_type,
        }
    }
}
