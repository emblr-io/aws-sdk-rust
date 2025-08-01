// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the subnet associated with a cluster. This parameter refers to subnets defined in Amazon Virtual Private Cloud (Amazon VPC) and used with ElastiCache.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Subnet {
    /// <p>The unique identifier for the subnet.</p>
    pub subnet_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The Availability Zone associated with the subnet.</p>
    pub subnet_availability_zone: ::std::option::Option<crate::types::AvailabilityZone>,
    /// <p>The outpost ARN of the subnet.</p>
    pub subnet_outpost: ::std::option::Option<crate::types::SubnetOutpost>,
    /// <p>Either <code>ipv4</code> | <code>ipv6</code> | <code>dual_stack</code>. IPv6 is supported for workloads using Valkey 7.2 and above, Redis OSS engine version 6.2 to 7.1 or Memcached engine version 1.6.6 and above on all instances built on the <a href="http://aws.amazon.com/ec2/nitro/">Nitro system</a>.</p>
    pub supported_network_types: ::std::option::Option<::std::vec::Vec<crate::types::NetworkType>>,
}
impl Subnet {
    /// <p>The unique identifier for the subnet.</p>
    pub fn subnet_identifier(&self) -> ::std::option::Option<&str> {
        self.subnet_identifier.as_deref()
    }
    /// <p>The Availability Zone associated with the subnet.</p>
    pub fn subnet_availability_zone(&self) -> ::std::option::Option<&crate::types::AvailabilityZone> {
        self.subnet_availability_zone.as_ref()
    }
    /// <p>The outpost ARN of the subnet.</p>
    pub fn subnet_outpost(&self) -> ::std::option::Option<&crate::types::SubnetOutpost> {
        self.subnet_outpost.as_ref()
    }
    /// <p>Either <code>ipv4</code> | <code>ipv6</code> | <code>dual_stack</code>. IPv6 is supported for workloads using Valkey 7.2 and above, Redis OSS engine version 6.2 to 7.1 or Memcached engine version 1.6.6 and above on all instances built on the <a href="http://aws.amazon.com/ec2/nitro/">Nitro system</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_network_types.is_none()`.
    pub fn supported_network_types(&self) -> &[crate::types::NetworkType] {
        self.supported_network_types.as_deref().unwrap_or_default()
    }
}
impl Subnet {
    /// Creates a new builder-style object to manufacture [`Subnet`](crate::types::Subnet).
    pub fn builder() -> crate::types::builders::SubnetBuilder {
        crate::types::builders::SubnetBuilder::default()
    }
}

/// A builder for [`Subnet`](crate::types::Subnet).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SubnetBuilder {
    pub(crate) subnet_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_availability_zone: ::std::option::Option<crate::types::AvailabilityZone>,
    pub(crate) subnet_outpost: ::std::option::Option<crate::types::SubnetOutpost>,
    pub(crate) supported_network_types: ::std::option::Option<::std::vec::Vec<crate::types::NetworkType>>,
}
impl SubnetBuilder {
    /// <p>The unique identifier for the subnet.</p>
    pub fn subnet_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the subnet.</p>
    pub fn set_subnet_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_identifier = input;
        self
    }
    /// <p>The unique identifier for the subnet.</p>
    pub fn get_subnet_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_identifier
    }
    /// <p>The Availability Zone associated with the subnet.</p>
    pub fn subnet_availability_zone(mut self, input: crate::types::AvailabilityZone) -> Self {
        self.subnet_availability_zone = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Availability Zone associated with the subnet.</p>
    pub fn set_subnet_availability_zone(mut self, input: ::std::option::Option<crate::types::AvailabilityZone>) -> Self {
        self.subnet_availability_zone = input;
        self
    }
    /// <p>The Availability Zone associated with the subnet.</p>
    pub fn get_subnet_availability_zone(&self) -> &::std::option::Option<crate::types::AvailabilityZone> {
        &self.subnet_availability_zone
    }
    /// <p>The outpost ARN of the subnet.</p>
    pub fn subnet_outpost(mut self, input: crate::types::SubnetOutpost) -> Self {
        self.subnet_outpost = ::std::option::Option::Some(input);
        self
    }
    /// <p>The outpost ARN of the subnet.</p>
    pub fn set_subnet_outpost(mut self, input: ::std::option::Option<crate::types::SubnetOutpost>) -> Self {
        self.subnet_outpost = input;
        self
    }
    /// <p>The outpost ARN of the subnet.</p>
    pub fn get_subnet_outpost(&self) -> &::std::option::Option<crate::types::SubnetOutpost> {
        &self.subnet_outpost
    }
    /// Appends an item to `supported_network_types`.
    ///
    /// To override the contents of this collection use [`set_supported_network_types`](Self::set_supported_network_types).
    ///
    /// <p>Either <code>ipv4</code> | <code>ipv6</code> | <code>dual_stack</code>. IPv6 is supported for workloads using Valkey 7.2 and above, Redis OSS engine version 6.2 to 7.1 or Memcached engine version 1.6.6 and above on all instances built on the <a href="http://aws.amazon.com/ec2/nitro/">Nitro system</a>.</p>
    pub fn supported_network_types(mut self, input: crate::types::NetworkType) -> Self {
        let mut v = self.supported_network_types.unwrap_or_default();
        v.push(input);
        self.supported_network_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>Either <code>ipv4</code> | <code>ipv6</code> | <code>dual_stack</code>. IPv6 is supported for workloads using Valkey 7.2 and above, Redis OSS engine version 6.2 to 7.1 or Memcached engine version 1.6.6 and above on all instances built on the <a href="http://aws.amazon.com/ec2/nitro/">Nitro system</a>.</p>
    pub fn set_supported_network_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NetworkType>>) -> Self {
        self.supported_network_types = input;
        self
    }
    /// <p>Either <code>ipv4</code> | <code>ipv6</code> | <code>dual_stack</code>. IPv6 is supported for workloads using Valkey 7.2 and above, Redis OSS engine version 6.2 to 7.1 or Memcached engine version 1.6.6 and above on all instances built on the <a href="http://aws.amazon.com/ec2/nitro/">Nitro system</a>.</p>
    pub fn get_supported_network_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NetworkType>> {
        &self.supported_network_types
    }
    /// Consumes the builder and constructs a [`Subnet`](crate::types::Subnet).
    pub fn build(self) -> crate::types::Subnet {
        crate::types::Subnet {
            subnet_identifier: self.subnet_identifier,
            subnet_availability_zone: self.subnet_availability_zone,
            subnet_outpost: self.subnet_outpost,
            supported_network_types: self.supported_network_types,
        }
    }
}
