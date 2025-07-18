// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Options to specify the subnets and security groups for VPC endpoint. For more information, see <a href="http://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/es-vpc.html" target="_blank"> VPC Endpoints for Amazon Elasticsearch Service Domains</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VpcDerivedInfo {
    /// <p>The VPC Id for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the subnets for VPC endpoint.</p>
    pub subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The availability zones for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Specifies the security groups for VPC endpoint.</p>
    pub security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl VpcDerivedInfo {
    /// <p>The VPC Id for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>Specifies the subnets for VPC endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ids.is_none()`.
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        self.subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The availability zones for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.availability_zones.is_none()`.
    pub fn availability_zones(&self) -> &[::std::string::String] {
        self.availability_zones.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the security groups for VPC endpoint.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_ids.is_none()`.
    pub fn security_group_ids(&self) -> &[::std::string::String] {
        self.security_group_ids.as_deref().unwrap_or_default()
    }
}
impl VpcDerivedInfo {
    /// Creates a new builder-style object to manufacture [`VpcDerivedInfo`](crate::types::VpcDerivedInfo).
    pub fn builder() -> crate::types::builders::VpcDerivedInfoBuilder {
        crate::types::builders::VpcDerivedInfoBuilder::default()
    }
}

/// A builder for [`VpcDerivedInfo`](crate::types::VpcDerivedInfo).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VpcDerivedInfoBuilder {
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) security_group_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl VpcDerivedInfoBuilder {
    /// <p>The VPC Id for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The VPC Id for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The VPC Id for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>Specifies the subnets for VPC endpoint.</p>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the subnets for VPC endpoint.</p>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>Specifies the subnets for VPC endpoint.</p>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// Appends an item to `availability_zones`.
    ///
    /// To override the contents of this collection use [`set_availability_zones`](Self::set_availability_zones).
    ///
    /// <p>The availability zones for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub fn availability_zones(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.availability_zones.unwrap_or_default();
        v.push(input.into());
        self.availability_zones = ::std::option::Option::Some(v);
        self
    }
    /// <p>The availability zones for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub fn set_availability_zones(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.availability_zones = input;
        self
    }
    /// <p>The availability zones for the Elasticsearch domain. Exists only if the domain was created with VPCOptions.</p>
    pub fn get_availability_zones(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.availability_zones
    }
    /// Appends an item to `security_group_ids`.
    ///
    /// To override the contents of this collection use [`set_security_group_ids`](Self::set_security_group_ids).
    ///
    /// <p>Specifies the security groups for VPC endpoint.</p>
    pub fn security_group_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_ids.unwrap_or_default();
        v.push(input.into());
        self.security_group_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the security groups for VPC endpoint.</p>
    pub fn set_security_group_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_ids = input;
        self
    }
    /// <p>Specifies the security groups for VPC endpoint.</p>
    pub fn get_security_group_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_ids
    }
    /// Consumes the builder and constructs a [`VpcDerivedInfo`](crate::types::VpcDerivedInfo).
    pub fn build(self) -> crate::types::VpcDerivedInfo {
        crate::types::VpcDerivedInfo {
            vpc_id: self.vpc_id,
            subnet_ids: self.subnet_ids,
            availability_zones: self.availability_zones,
            security_group_ids: self.security_group_ids,
        }
    }
}
