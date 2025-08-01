// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configurations related to encryption for the security configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EncryptionConfiguration {
    /// <p>In-transit encryption-related input for the security configuration.</p>
    pub in_transit_encryption_configuration: ::std::option::Option<crate::types::InTransitEncryptionConfiguration>,
}
impl EncryptionConfiguration {
    /// <p>In-transit encryption-related input for the security configuration.</p>
    pub fn in_transit_encryption_configuration(&self) -> ::std::option::Option<&crate::types::InTransitEncryptionConfiguration> {
        self.in_transit_encryption_configuration.as_ref()
    }
}
impl EncryptionConfiguration {
    /// Creates a new builder-style object to manufacture [`EncryptionConfiguration`](crate::types::EncryptionConfiguration).
    pub fn builder() -> crate::types::builders::EncryptionConfigurationBuilder {
        crate::types::builders::EncryptionConfigurationBuilder::default()
    }
}

/// A builder for [`EncryptionConfiguration`](crate::types::EncryptionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EncryptionConfigurationBuilder {
    pub(crate) in_transit_encryption_configuration: ::std::option::Option<crate::types::InTransitEncryptionConfiguration>,
}
impl EncryptionConfigurationBuilder {
    /// <p>In-transit encryption-related input for the security configuration.</p>
    pub fn in_transit_encryption_configuration(mut self, input: crate::types::InTransitEncryptionConfiguration) -> Self {
        self.in_transit_encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>In-transit encryption-related input for the security configuration.</p>
    pub fn set_in_transit_encryption_configuration(mut self, input: ::std::option::Option<crate::types::InTransitEncryptionConfiguration>) -> Self {
        self.in_transit_encryption_configuration = input;
        self
    }
    /// <p>In-transit encryption-related input for the security configuration.</p>
    pub fn get_in_transit_encryption_configuration(&self) -> &::std::option::Option<crate::types::InTransitEncryptionConfiguration> {
        &self.in_transit_encryption_configuration
    }
    /// Consumes the builder and constructs a [`EncryptionConfiguration`](crate::types::EncryptionConfiguration).
    pub fn build(self) -> crate::types::EncryptionConfiguration {
        crate::types::EncryptionConfiguration {
            in_transit_encryption_configuration: self.in_transit_encryption_configuration,
        }
    }
}
