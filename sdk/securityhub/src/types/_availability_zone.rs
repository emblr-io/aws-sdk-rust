// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an Availability Zone.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AvailabilityZone {
    /// <p>The name of the Availability Zone.</p>
    pub zone_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the subnet. You can specify one subnet per Availability Zone.</p>
    pub subnet_id: ::std::option::Option<::std::string::String>,
}
impl AvailabilityZone {
    /// <p>The name of the Availability Zone.</p>
    pub fn zone_name(&self) -> ::std::option::Option<&str> {
        self.zone_name.as_deref()
    }
    /// <p>The ID of the subnet. You can specify one subnet per Availability Zone.</p>
    pub fn subnet_id(&self) -> ::std::option::Option<&str> {
        self.subnet_id.as_deref()
    }
}
impl AvailabilityZone {
    /// Creates a new builder-style object to manufacture [`AvailabilityZone`](crate::types::AvailabilityZone).
    pub fn builder() -> crate::types::builders::AvailabilityZoneBuilder {
        crate::types::builders::AvailabilityZoneBuilder::default()
    }
}

/// A builder for [`AvailabilityZone`](crate::types::AvailabilityZone).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AvailabilityZoneBuilder {
    pub(crate) zone_name: ::std::option::Option<::std::string::String>,
    pub(crate) subnet_id: ::std::option::Option<::std::string::String>,
}
impl AvailabilityZoneBuilder {
    /// <p>The name of the Availability Zone.</p>
    pub fn zone_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.zone_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Availability Zone.</p>
    pub fn set_zone_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.zone_name = input;
        self
    }
    /// <p>The name of the Availability Zone.</p>
    pub fn get_zone_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.zone_name
    }
    /// <p>The ID of the subnet. You can specify one subnet per Availability Zone.</p>
    pub fn subnet_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subnet_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the subnet. You can specify one subnet per Availability Zone.</p>
    pub fn set_subnet_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subnet_id = input;
        self
    }
    /// <p>The ID of the subnet. You can specify one subnet per Availability Zone.</p>
    pub fn get_subnet_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.subnet_id
    }
    /// Consumes the builder and constructs a [`AvailabilityZone`](crate::types::AvailabilityZone).
    pub fn build(self) -> crate::types::AvailabilityZone {
        crate::types::AvailabilityZone {
            zone_name: self.zone_name,
            subnet_id: self.subnet_id,
        }
    }
}
