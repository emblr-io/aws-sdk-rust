// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the additional configuration for a feature in your GuardDuty account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetectorAdditionalConfiguration {
    /// <p>Name of the additional configuration.</p>
    pub name: ::std::option::Option<crate::types::FeatureAdditionalConfiguration>,
    /// <p>Status of the additional configuration.</p>
    pub status: ::std::option::Option<crate::types::FeatureStatus>,
}
impl DetectorAdditionalConfiguration {
    /// <p>Name of the additional configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::FeatureAdditionalConfiguration> {
        self.name.as_ref()
    }
    /// <p>Status of the additional configuration.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::FeatureStatus> {
        self.status.as_ref()
    }
}
impl DetectorAdditionalConfiguration {
    /// Creates a new builder-style object to manufacture [`DetectorAdditionalConfiguration`](crate::types::DetectorAdditionalConfiguration).
    pub fn builder() -> crate::types::builders::DetectorAdditionalConfigurationBuilder {
        crate::types::builders::DetectorAdditionalConfigurationBuilder::default()
    }
}

/// A builder for [`DetectorAdditionalConfiguration`](crate::types::DetectorAdditionalConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetectorAdditionalConfigurationBuilder {
    pub(crate) name: ::std::option::Option<crate::types::FeatureAdditionalConfiguration>,
    pub(crate) status: ::std::option::Option<crate::types::FeatureStatus>,
}
impl DetectorAdditionalConfigurationBuilder {
    /// <p>Name of the additional configuration.</p>
    pub fn name(mut self, input: crate::types::FeatureAdditionalConfiguration) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>Name of the additional configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::FeatureAdditionalConfiguration>) -> Self {
        self.name = input;
        self
    }
    /// <p>Name of the additional configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::FeatureAdditionalConfiguration> {
        &self.name
    }
    /// <p>Status of the additional configuration.</p>
    pub fn status(mut self, input: crate::types::FeatureStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Status of the additional configuration.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FeatureStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Status of the additional configuration.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FeatureStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`DetectorAdditionalConfiguration`](crate::types::DetectorAdditionalConfiguration).
    pub fn build(self) -> crate::types::DetectorAdditionalConfiguration {
        crate::types::DetectorAdditionalConfiguration {
            name: self.name,
            status: self.status,
        }
    }
}
