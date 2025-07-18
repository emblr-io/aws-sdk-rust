// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the directory.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DirectoryVpcSettingsDescription {
    /// <p>The identifier of the VPC that the directory is in.</p>
    pub vpc_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifiers of the subnets for the directory servers.</p>
    pub subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The domain controller security group identifier for the directory.</p>
    pub security_group_id: ::std::option::Option<::std::string::String>,
    /// <p>The list of Availability Zones that the directory is in.</p>
    pub availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DirectoryVpcSettingsDescription {
    /// <p>The identifier of the VPC that the directory is in.</p>
    pub fn vpc_id(&self) -> ::std::option::Option<&str> {
        self.vpc_id.as_deref()
    }
    /// <p>The identifiers of the subnets for the directory servers.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subnet_ids.is_none()`.
    pub fn subnet_ids(&self) -> &[::std::string::String] {
        self.subnet_ids.as_deref().unwrap_or_default()
    }
    /// <p>The domain controller security group identifier for the directory.</p>
    pub fn security_group_id(&self) -> ::std::option::Option<&str> {
        self.security_group_id.as_deref()
    }
    /// <p>The list of Availability Zones that the directory is in.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.availability_zones.is_none()`.
    pub fn availability_zones(&self) -> &[::std::string::String] {
        self.availability_zones.as_deref().unwrap_or_default()
    }
}
impl DirectoryVpcSettingsDescription {
    /// Creates a new builder-style object to manufacture [`DirectoryVpcSettingsDescription`](crate::types::DirectoryVpcSettingsDescription).
    pub fn builder() -> crate::types::builders::DirectoryVpcSettingsDescriptionBuilder {
        crate::types::builders::DirectoryVpcSettingsDescriptionBuilder::default()
    }
}

/// A builder for [`DirectoryVpcSettingsDescription`](crate::types::DirectoryVpcSettingsDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DirectoryVpcSettingsDescriptionBuilder {
    pub(crate) vpc_id: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) security_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) availability_zones: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DirectoryVpcSettingsDescriptionBuilder {
    /// <p>The identifier of the VPC that the directory is in.</p>
    pub fn vpc_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vpc_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the VPC that the directory is in.</p>
    pub fn set_vpc_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vpc_id = input;
        self
    }
    /// <p>The identifier of the VPC that the directory is in.</p>
    pub fn get_vpc_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.vpc_id
    }
    /// Appends an item to `subnet_ids`.
    ///
    /// To override the contents of this collection use [`set_subnet_ids`](Self::set_subnet_ids).
    ///
    /// <p>The identifiers of the subnets for the directory servers.</p>
    pub fn subnet_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnet_ids.unwrap_or_default();
        v.push(input.into());
        self.subnet_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The identifiers of the subnets for the directory servers.</p>
    pub fn set_subnet_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnet_ids = input;
        self
    }
    /// <p>The identifiers of the subnets for the directory servers.</p>
    pub fn get_subnet_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnet_ids
    }
    /// <p>The domain controller security group identifier for the directory.</p>
    pub fn security_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.security_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain controller security group identifier for the directory.</p>
    pub fn set_security_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.security_group_id = input;
        self
    }
    /// <p>The domain controller security group identifier for the directory.</p>
    pub fn get_security_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.security_group_id
    }
    /// Appends an item to `availability_zones`.
    ///
    /// To override the contents of this collection use [`set_availability_zones`](Self::set_availability_zones).
    ///
    /// <p>The list of Availability Zones that the directory is in.</p>
    pub fn availability_zones(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.availability_zones.unwrap_or_default();
        v.push(input.into());
        self.availability_zones = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of Availability Zones that the directory is in.</p>
    pub fn set_availability_zones(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.availability_zones = input;
        self
    }
    /// <p>The list of Availability Zones that the directory is in.</p>
    pub fn get_availability_zones(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.availability_zones
    }
    /// Consumes the builder and constructs a [`DirectoryVpcSettingsDescription`](crate::types::DirectoryVpcSettingsDescription).
    pub fn build(self) -> crate::types::DirectoryVpcSettingsDescription {
        crate::types::DirectoryVpcSettingsDescription {
            vpc_id: self.vpc_id,
            subnet_ids: self.subnet_ids,
            security_group_id: self.security_group_id,
            availability_zones: self.availability_zones,
        }
    }
}
