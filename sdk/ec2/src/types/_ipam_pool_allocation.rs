// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>In IPAM, an allocation is a CIDR assignment from an IPAM pool to another IPAM pool or to a resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IpamPoolAllocation {
    /// <p>The CIDR for the allocation. A CIDR is a representation of an IP address and its associated network mask (or netmask) and refers to a range of IP addresses. An IPv4 CIDR example is <code>10.24.34.0/23</code>. An IPv6 CIDR example is <code>2001:DB8::/32</code>.</p>
    pub cidr: ::std::option::Option<::std::string::String>,
    /// <p>The ID of an allocation.</p>
    pub ipam_pool_allocation_id: ::std::option::Option<::std::string::String>,
    /// <p>A description of the pool allocation.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the resource.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of the resource.</p>
    pub resource_type: ::std::option::Option<crate::types::IpamPoolAllocationResourceType>,
    /// <p>The Amazon Web Services Region of the resource.</p>
    pub resource_region: ::std::option::Option<::std::string::String>,
    /// <p>The owner of the resource.</p>
    pub resource_owner: ::std::option::Option<::std::string::String>,
}
impl IpamPoolAllocation {
    /// <p>The CIDR for the allocation. A CIDR is a representation of an IP address and its associated network mask (or netmask) and refers to a range of IP addresses. An IPv4 CIDR example is <code>10.24.34.0/23</code>. An IPv6 CIDR example is <code>2001:DB8::/32</code>.</p>
    pub fn cidr(&self) -> ::std::option::Option<&str> {
        self.cidr.as_deref()
    }
    /// <p>The ID of an allocation.</p>
    pub fn ipam_pool_allocation_id(&self) -> ::std::option::Option<&str> {
        self.ipam_pool_allocation_id.as_deref()
    }
    /// <p>A description of the pool allocation.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ID of the resource.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>The type of the resource.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::IpamPoolAllocationResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>The Amazon Web Services Region of the resource.</p>
    pub fn resource_region(&self) -> ::std::option::Option<&str> {
        self.resource_region.as_deref()
    }
    /// <p>The owner of the resource.</p>
    pub fn resource_owner(&self) -> ::std::option::Option<&str> {
        self.resource_owner.as_deref()
    }
}
impl IpamPoolAllocation {
    /// Creates a new builder-style object to manufacture [`IpamPoolAllocation`](crate::types::IpamPoolAllocation).
    pub fn builder() -> crate::types::builders::IpamPoolAllocationBuilder {
        crate::types::builders::IpamPoolAllocationBuilder::default()
    }
}

/// A builder for [`IpamPoolAllocation`](crate::types::IpamPoolAllocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IpamPoolAllocationBuilder {
    pub(crate) cidr: ::std::option::Option<::std::string::String>,
    pub(crate) ipam_pool_allocation_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<crate::types::IpamPoolAllocationResourceType>,
    pub(crate) resource_region: ::std::option::Option<::std::string::String>,
    pub(crate) resource_owner: ::std::option::Option<::std::string::String>,
}
impl IpamPoolAllocationBuilder {
    /// <p>The CIDR for the allocation. A CIDR is a representation of an IP address and its associated network mask (or netmask) and refers to a range of IP addresses. An IPv4 CIDR example is <code>10.24.34.0/23</code>. An IPv6 CIDR example is <code>2001:DB8::/32</code>.</p>
    pub fn cidr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cidr = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The CIDR for the allocation. A CIDR is a representation of an IP address and its associated network mask (or netmask) and refers to a range of IP addresses. An IPv4 CIDR example is <code>10.24.34.0/23</code>. An IPv6 CIDR example is <code>2001:DB8::/32</code>.</p>
    pub fn set_cidr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cidr = input;
        self
    }
    /// <p>The CIDR for the allocation. A CIDR is a representation of an IP address and its associated network mask (or netmask) and refers to a range of IP addresses. An IPv4 CIDR example is <code>10.24.34.0/23</code>. An IPv6 CIDR example is <code>2001:DB8::/32</code>.</p>
    pub fn get_cidr(&self) -> &::std::option::Option<::std::string::String> {
        &self.cidr
    }
    /// <p>The ID of an allocation.</p>
    pub fn ipam_pool_allocation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ipam_pool_allocation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an allocation.</p>
    pub fn set_ipam_pool_allocation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ipam_pool_allocation_id = input;
        self
    }
    /// <p>The ID of an allocation.</p>
    pub fn get_ipam_pool_allocation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ipam_pool_allocation_id
    }
    /// <p>A description of the pool allocation.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the pool allocation.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the pool allocation.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The ID of the resource.</p>
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the resource.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The ID of the resource.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// <p>The type of the resource.</p>
    pub fn resource_type(mut self, input: crate::types::IpamPoolAllocationResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of the resource.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::IpamPoolAllocationResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The type of the resource.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::IpamPoolAllocationResourceType> {
        &self.resource_type
    }
    /// <p>The Amazon Web Services Region of the resource.</p>
    pub fn resource_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services Region of the resource.</p>
    pub fn set_resource_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_region = input;
        self
    }
    /// <p>The Amazon Web Services Region of the resource.</p>
    pub fn get_resource_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_region
    }
    /// <p>The owner of the resource.</p>
    pub fn resource_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The owner of the resource.</p>
    pub fn set_resource_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_owner = input;
        self
    }
    /// <p>The owner of the resource.</p>
    pub fn get_resource_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_owner
    }
    /// Consumes the builder and constructs a [`IpamPoolAllocation`](crate::types::IpamPoolAllocation).
    pub fn build(self) -> crate::types::IpamPoolAllocation {
        crate::types::IpamPoolAllocation {
            cidr: self.cidr,
            ipam_pool_allocation_id: self.ipam_pool_allocation_id,
            description: self.description,
            resource_id: self.resource_id,
            resource_type: self.resource_type,
            resource_region: self.resource_region,
            resource_owner: self.resource_owner,
        }
    }
}
