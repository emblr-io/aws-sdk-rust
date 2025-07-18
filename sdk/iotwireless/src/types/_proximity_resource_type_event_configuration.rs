// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Proximity resource type event configuration object for enabling or disabling topic.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProximityResourceTypeEventConfiguration {
    /// <p>Proximity resource type event configuration object for enabling and disabling wireless device topic.</p>
    pub sidewalk: ::std::option::Option<crate::types::SidewalkResourceTypeEventConfiguration>,
}
impl ProximityResourceTypeEventConfiguration {
    /// <p>Proximity resource type event configuration object for enabling and disabling wireless device topic.</p>
    pub fn sidewalk(&self) -> ::std::option::Option<&crate::types::SidewalkResourceTypeEventConfiguration> {
        self.sidewalk.as_ref()
    }
}
impl ProximityResourceTypeEventConfiguration {
    /// Creates a new builder-style object to manufacture [`ProximityResourceTypeEventConfiguration`](crate::types::ProximityResourceTypeEventConfiguration).
    pub fn builder() -> crate::types::builders::ProximityResourceTypeEventConfigurationBuilder {
        crate::types::builders::ProximityResourceTypeEventConfigurationBuilder::default()
    }
}

/// A builder for [`ProximityResourceTypeEventConfiguration`](crate::types::ProximityResourceTypeEventConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProximityResourceTypeEventConfigurationBuilder {
    pub(crate) sidewalk: ::std::option::Option<crate::types::SidewalkResourceTypeEventConfiguration>,
}
impl ProximityResourceTypeEventConfigurationBuilder {
    /// <p>Proximity resource type event configuration object for enabling and disabling wireless device topic.</p>
    pub fn sidewalk(mut self, input: crate::types::SidewalkResourceTypeEventConfiguration) -> Self {
        self.sidewalk = ::std::option::Option::Some(input);
        self
    }
    /// <p>Proximity resource type event configuration object for enabling and disabling wireless device topic.</p>
    pub fn set_sidewalk(mut self, input: ::std::option::Option<crate::types::SidewalkResourceTypeEventConfiguration>) -> Self {
        self.sidewalk = input;
        self
    }
    /// <p>Proximity resource type event configuration object for enabling and disabling wireless device topic.</p>
    pub fn get_sidewalk(&self) -> &::std::option::Option<crate::types::SidewalkResourceTypeEventConfiguration> {
        &self.sidewalk
    }
    /// Consumes the builder and constructs a [`ProximityResourceTypeEventConfiguration`](crate::types::ProximityResourceTypeEventConfiguration).
    pub fn build(self) -> crate::types::ProximityResourceTypeEventConfiguration {
        crate::types::ProximityResourceTypeEventConfiguration { sidewalk: self.sidewalk }
    }
}
