// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the privacy configuration for a configured model algorithm association.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PrivacyConfiguration {
    /// <p>The privacy configuration policies for a configured model algorithm association.</p>
    pub policies: ::std::option::Option<crate::types::PrivacyConfigurationPolicies>,
}
impl PrivacyConfiguration {
    /// <p>The privacy configuration policies for a configured model algorithm association.</p>
    pub fn policies(&self) -> ::std::option::Option<&crate::types::PrivacyConfigurationPolicies> {
        self.policies.as_ref()
    }
}
impl PrivacyConfiguration {
    /// Creates a new builder-style object to manufacture [`PrivacyConfiguration`](crate::types::PrivacyConfiguration).
    pub fn builder() -> crate::types::builders::PrivacyConfigurationBuilder {
        crate::types::builders::PrivacyConfigurationBuilder::default()
    }
}

/// A builder for [`PrivacyConfiguration`](crate::types::PrivacyConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PrivacyConfigurationBuilder {
    pub(crate) policies: ::std::option::Option<crate::types::PrivacyConfigurationPolicies>,
}
impl PrivacyConfigurationBuilder {
    /// <p>The privacy configuration policies for a configured model algorithm association.</p>
    /// This field is required.
    pub fn policies(mut self, input: crate::types::PrivacyConfigurationPolicies) -> Self {
        self.policies = ::std::option::Option::Some(input);
        self
    }
    /// <p>The privacy configuration policies for a configured model algorithm association.</p>
    pub fn set_policies(mut self, input: ::std::option::Option<crate::types::PrivacyConfigurationPolicies>) -> Self {
        self.policies = input;
        self
    }
    /// <p>The privacy configuration policies for a configured model algorithm association.</p>
    pub fn get_policies(&self) -> &::std::option::Option<crate::types::PrivacyConfigurationPolicies> {
        &self.policies
    }
    /// Consumes the builder and constructs a [`PrivacyConfiguration`](crate::types::PrivacyConfiguration).
    pub fn build(self) -> crate::types::PrivacyConfiguration {
        crate::types::PrivacyConfiguration { policies: self.policies }
    }
}
