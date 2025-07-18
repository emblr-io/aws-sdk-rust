// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Multiplex MediaConnect output destination settings.
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MultiplexMediaConnectOutputDestinationSettings {
    /// The MediaConnect entitlement ARN available as a Flow source.
    pub entitlement_arn: ::std::option::Option<::std::string::String>,
}
impl MultiplexMediaConnectOutputDestinationSettings {
    /// The MediaConnect entitlement ARN available as a Flow source.
    pub fn entitlement_arn(&self) -> ::std::option::Option<&str> {
        self.entitlement_arn.as_deref()
    }
}
impl MultiplexMediaConnectOutputDestinationSettings {
    /// Creates a new builder-style object to manufacture [`MultiplexMediaConnectOutputDestinationSettings`](crate::types::MultiplexMediaConnectOutputDestinationSettings).
    pub fn builder() -> crate::types::builders::MultiplexMediaConnectOutputDestinationSettingsBuilder {
        crate::types::builders::MultiplexMediaConnectOutputDestinationSettingsBuilder::default()
    }
}

/// A builder for [`MultiplexMediaConnectOutputDestinationSettings`](crate::types::MultiplexMediaConnectOutputDestinationSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MultiplexMediaConnectOutputDestinationSettingsBuilder {
    pub(crate) entitlement_arn: ::std::option::Option<::std::string::String>,
}
impl MultiplexMediaConnectOutputDestinationSettingsBuilder {
    /// The MediaConnect entitlement ARN available as a Flow source.
    pub fn entitlement_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entitlement_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// The MediaConnect entitlement ARN available as a Flow source.
    pub fn set_entitlement_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entitlement_arn = input;
        self
    }
    /// The MediaConnect entitlement ARN available as a Flow source.
    pub fn get_entitlement_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.entitlement_arn
    }
    /// Consumes the builder and constructs a [`MultiplexMediaConnectOutputDestinationSettings`](crate::types::MultiplexMediaConnectOutputDestinationSettings).
    pub fn build(self) -> crate::types::MultiplexMediaConnectOutputDestinationSettings {
        crate::types::MultiplexMediaConnectOutputDestinationSettings {
            entitlement_arn: self.entitlement_arn,
        }
    }
}
