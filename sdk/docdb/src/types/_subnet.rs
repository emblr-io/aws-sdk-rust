// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Detailed information about a subnet.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Subnet {
    /// <p>Specifies the identifier of the subnet.</p>
    pub subnet_identifier: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the Availability Zone for the subnet.</p>
    pub subnet_availability_zone: ::std::option::Option<crate::types::AvailabilityZone>,
    /// <p>Specifies the status of the subnet.</p>
    pub subnet_status: ::std::option::Option<::std::string::String>,
}
impl Subnet {
    /// <p>Specifies the identifier of the subnet.</p>
    pub fn subnet_identifier(&self) -> ::std::option::Option<&str> {
        self.subnet_identifier.as_deref()
    }
    /// <p>Specifies the Availability Zone for the subnet.</p>
    pub fn subnet_availability_zone(&self) -> ::std::option::Option<&crate::types::AvailabilityZone> {
        self.subnet_availability_zone.as_ref()
    }
    /// <p>Specifies the status of the subnet.</p>
    pub fn subnet_status(&self) -> ::std::option::Option<&str> {
        self.subnet_status.as_deref()
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
    pub(crate) subnet_status: ::std::option::Option<::std::string::String>,
}
impl SubnetBuilder {
    /// <p>Specifies the identifier of the subnet.</p>
    pub fn subnet_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the identifier of the subnet.</p>
    pub fn set_subnet_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_identifier = input;
        self
    }
    /// <p>Specifies the identifier of the subnet.</p>
    pub fn get_subnet_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_identifier
    }
    /// <p>Specifies the Availability Zone for the subnet.</p>
    pub fn subnet_availability_zone(mut self, input: crate::types::AvailabilityZone) -> Self {
        self.subnet_availability_zone = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the Availability Zone for the subnet.</p>
    pub fn set_subnet_availability_zone(mut self, input: ::std::option::Option<crate::types::AvailabilityZone>) -> Self {
        self.subnet_availability_zone = input;
        self
    }
    /// <p>Specifies the Availability Zone for the subnet.</p>
    pub fn get_subnet_availability_zone(&self) -> &::std::option::Option<crate::types::AvailabilityZone> {
        &self.subnet_availability_zone
    }
    /// <p>Specifies the status of the subnet.</p>
    pub fn subnet_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the status of the subnet.</p>
    pub fn set_subnet_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_status = input;
        self
    }
    /// <p>Specifies the status of the subnet.</p>
    pub fn get_subnet_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_status
    }
    /// Consumes the builder and constructs a [`Subnet`](crate::types::Subnet).
    pub fn build(self) -> crate::types::Subnet {
        crate::types::Subnet {
            subnet_identifier: self.subnet_identifier,
            subnet_availability_zone: self.subnet_availability_zone,
            subnet_status: self.subnet_status,
        }
    }
}
