// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a subnet group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ClusterSubnetGroup {
    /// <p>The name of the cluster subnet group.</p>
    pub cluster_subnet_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the cluster subnet group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The VPC ID of the cluster subnet group.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>The status of the cluster subnet group. Possible values are <code>Complete</code>, <code>Incomplete</code> and <code>Invalid</code>.</p>
    pub subnet_group_status: ::std::option::Option<::std::string::String>,
    /// <p>A list of the VPC <code>Subnet</code> elements.</p>
    pub subnets: ::std::option::Option<::std::vec::Vec<crate::types::Subnet>>,
    /// <p>The list of tags for the cluster subnet group.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The IP address types supported by this cluster subnet group. Possible values are <code>ipv4</code> and <code>dualstack</code>.</p>
    pub supported_cluster_ip_address_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ClusterSubnetGroup {
    /// <p>The name of the cluster subnet group.</p>
    pub fn cluster_subnet_group_name(&self) -> ::std::option::Option<&str> {
        self.cluster_subnet_group_name.as_deref()
    }
    /// <p>The description of the cluster subnet group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The VPC ID of the cluster subnet group.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>The status of the cluster subnet group. Possible values are <code>Complete</code>, <code>Incomplete</code> and <code>Invalid</code>.</p>
    pub fn subnet_group_status(&self) -> ::std::option::Option<&str> {
        self.subnet_group_status.as_deref()
    }
    /// <p>A list of the VPC <code>Subnet</code> elements.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnets.is_none()`.
    pub fn subnets(&self) -> &[crate::types::Subnet] {
        self.subnets.as_deref().unwrap_or_default()
    }
    /// <p>The list of tags for the cluster subnet group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The IP address types supported by this cluster subnet group. Possible values are <code>ipv4</code> and <code>dualstack</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_cluster_ip_address_types.is_none()`.
    pub fn supported_cluster_ip_address_types(&self) -> &[::std::string::String] {
        self.supported_cluster_ip_address_types.as_deref().unwrap_or_default()
    }
}
impl ClusterSubnetGroup {
    /// Creates a new builder-style object to manufacture [`ClusterSubnetGroup`](crate::types::ClusterSubnetGroup).
    pub fn builder() -> crate::types::builders::ClusterSubnetGroupBuilder {
        crate::types::builders::ClusterSubnetGroupBuilder::default()
    }
}

/// A builder for [`ClusterSubnetGroup`](crate::types::ClusterSubnetGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ClusterSubnetGroupBuilder {
    pub(crate) cluster_subnet_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_group_status: ::std::option::Option<::std::string::String>,
    pub(crate) subnets: ::std::option::Option<::std::vec::Vec<crate::types::Subnet>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) supported_cluster_ip_address_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ClusterSubnetGroupBuilder {
    /// <p>The name of the cluster subnet group.</p>
    pub fn cluster_subnet_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_subnet_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the cluster subnet group.</p>
    pub fn set_cluster_subnet_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_subnet_group_name = input;
        self
    }
    /// <p>The name of the cluster subnet group.</p>
    pub fn get_cluster_subnet_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_subnet_group_name
    }
    /// <p>The description of the cluster subnet group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the cluster subnet group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the cluster subnet group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The VPC ID of the cluster subnet group.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The VPC ID of the cluster subnet group.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The VPC ID of the cluster subnet group.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// <p>The status of the cluster subnet group. Possible values are <code>Complete</code>, <code>Incomplete</code> and <code>Invalid</code>.</p>
    pub fn subnet_group_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_group_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the cluster subnet group. Possible values are <code>Complete</code>, <code>Incomplete</code> and <code>Invalid</code>.</p>
    pub fn set_subnet_group_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_group_status = input;
        self
    }
    /// <p>The status of the cluster subnet group. Possible values are <code>Complete</code>, <code>Incomplete</code> and <code>Invalid</code>.</p>
    pub fn get_subnet_group_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_group_status
    }
    /// Appends an item to `subnets`.
    ///
    /// To override the contents of this collection use [`set_subnets`](Self::set_subnets).
    ///
    /// <p>A list of the VPC <code>Subnet</code> elements.</p>
    pub fn subnets(mut self, input: crate::types::Subnet) -> Self {
        let mut v = self.subnets.unwrap_or_default();
        v.push(input);
        self.subnets = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the VPC <code>Subnet</code> elements.</p>
    pub fn set_subnets(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Subnet>>) -> Self {
        self.subnets = input;
        self
    }
    /// <p>A list of the VPC <code>Subnet</code> elements.</p>
    pub fn get_subnets(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Subnet>> {
        &self.subnets
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The list of tags for the cluster subnet group.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of tags for the cluster subnet group.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The list of tags for the cluster subnet group.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Appends an item to `supported_cluster_ip_address_types`.
    ///
    /// To override the contents of this collection use [`set_supported_cluster_ip_address_types`](Self::set_supported_cluster_ip_address_types).
    ///
    /// <p>The IP address types supported by this cluster subnet group. Possible values are <code>ipv4</code> and <code>dualstack</code>.</p>
    pub fn supported_cluster_ip_address_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.supported_cluster_ip_address_types.unwrap_or_default();
        v.push(input.into());
        self.supported_cluster_ip_address_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IP address types supported by this cluster subnet group. Possible values are <code>ipv4</code> and <code>dualstack</code>.</p>
    pub fn set_supported_cluster_ip_address_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.supported_cluster_ip_address_types = input;
        self
    }
    /// <p>The IP address types supported by this cluster subnet group. Possible values are <code>ipv4</code> and <code>dualstack</code>.</p>
    pub fn get_supported_cluster_ip_address_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.supported_cluster_ip_address_types
    }
    /// Consumes the builder and constructs a [`ClusterSubnetGroup`](crate::types::ClusterSubnetGroup).
    pub fn build(self) -> crate::types::ClusterSubnetGroup {
        crate::types::ClusterSubnetGroup {
            cluster_subnet_group_name: self.cluster_subnet_group_name,
            description: self.description,
            vpc_id: self.vpc_id,
            subnet_group_status: self.subnet_group_status,
            subnets: self.subnets,
            tags: self.tags,
            supported_cluster_ip_address_types: self.supported_cluster_ip_address_types,
        }
    }
}
