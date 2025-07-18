// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the zone awareness configuration for the domain cluster, such as the number of availability zones.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ZoneAwarenessConfig {
    /// <p>An integer value to indicate the number of availability zones for a domain when zone awareness is enabled. This should be equal to number of subnets if VPC endpoints is enabled</p>
    pub availability_zone_count: ::std::option::Option<i32>,
}
impl ZoneAwarenessConfig {
    /// <p>An integer value to indicate the number of availability zones for a domain when zone awareness is enabled. This should be equal to number of subnets if VPC endpoints is enabled</p>
    pub fn availability_zone_count(&self) -> ::std::option::Option<i32> {
        self.availability_zone_count
    }
}
impl ZoneAwarenessConfig {
    /// Creates a new builder-style object to manufacture [`ZoneAwarenessConfig`](crate::types::ZoneAwarenessConfig).
    pub fn builder() -> crate::types::builders::ZoneAwarenessConfigBuilder {
        crate::types::builders::ZoneAwarenessConfigBuilder::default()
    }
}

/// A builder for [`ZoneAwarenessConfig`](crate::types::ZoneAwarenessConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ZoneAwarenessConfigBuilder {
    pub(crate) availability_zone_count: ::std::option::Option<i32>,
}
impl ZoneAwarenessConfigBuilder {
    /// <p>An integer value to indicate the number of availability zones for a domain when zone awareness is enabled. This should be equal to number of subnets if VPC endpoints is enabled</p>
    pub fn availability_zone_count(mut self, input: i32) -> Self {
        self.availability_zone_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>An integer value to indicate the number of availability zones for a domain when zone awareness is enabled. This should be equal to number of subnets if VPC endpoints is enabled</p>
    pub fn set_availability_zone_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.availability_zone_count = input;
        self
    }
    /// <p>An integer value to indicate the number of availability zones for a domain when zone awareness is enabled. This should be equal to number of subnets if VPC endpoints is enabled</p>
    pub fn get_availability_zone_count(&self) -> &::std::option::Option<i32> {
        &self.availability_zone_count
    }
    /// Consumes the builder and constructs a [`ZoneAwarenessConfig`](crate::types::ZoneAwarenessConfig).
    pub fn build(self) -> crate::types::ZoneAwarenessConfig {
        crate::types::ZoneAwarenessConfig {
            availability_zone_count: self.availability_zone_count,
        }
    }
}
