// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the features for the member account.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MemberFeaturesConfigurationResult {
    /// <p>Indicates the name of the feature that is enabled for the detector.</p>
    pub name: ::std::option::Option<crate::types::OrgFeature>,
    /// <p>Indicates the status of the feature that is enabled for the detector.</p>
    pub status: ::std::option::Option<crate::types::FeatureStatus>,
    /// <p>The timestamp at which the feature object was updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Indicates the additional configuration of the feature that is configured for the member account.</p>
    pub additional_configuration: ::std::option::Option<::std::vec::Vec<crate::types::MemberAdditionalConfigurationResult>>,
}
impl MemberFeaturesConfigurationResult {
    /// <p>Indicates the name of the feature that is enabled for the detector.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::OrgFeature> {
        self.name.as_ref()
    }
    /// <p>Indicates the status of the feature that is enabled for the detector.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::FeatureStatus> {
        self.status.as_ref()
    }
    /// <p>The timestamp at which the feature object was updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>Indicates the additional configuration of the feature that is configured for the member account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.additional_configuration.is_none()`.
    pub fn additional_configuration(&self) -> &[crate::types::MemberAdditionalConfigurationResult] {
        self.additional_configuration.as_deref().unwrap_or_default()
    }
}
impl MemberFeaturesConfigurationResult {
    /// Creates a new builder-style object to manufacture [`MemberFeaturesConfigurationResult`](crate::types::MemberFeaturesConfigurationResult).
    pub fn builder() -> crate::types::builders::MemberFeaturesConfigurationResultBuilder {
        crate::types::builders::MemberFeaturesConfigurationResultBuilder::default()
    }
}

/// A builder for [`MemberFeaturesConfigurationResult`](crate::types::MemberFeaturesConfigurationResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MemberFeaturesConfigurationResultBuilder {
    pub(crate) name: ::std::option::Option<crate::types::OrgFeature>,
    pub(crate) status: ::std::option::Option<crate::types::FeatureStatus>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) additional_configuration: ::std::option::Option<::std::vec::Vec<crate::types::MemberAdditionalConfigurationResult>>,
}
impl MemberFeaturesConfigurationResultBuilder {
    /// <p>Indicates the name of the feature that is enabled for the detector.</p>
    pub fn name(mut self, input: crate::types::OrgFeature) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the name of the feature that is enabled for the detector.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::OrgFeature>) -> Self {
        self.name = input;
        self
    }
    /// <p>Indicates the name of the feature that is enabled for the detector.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::OrgFeature> {
        &self.name
    }
    /// <p>Indicates the status of the feature that is enabled for the detector.</p>
    pub fn status(mut self, input: crate::types::FeatureStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the status of the feature that is enabled for the detector.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::FeatureStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Indicates the status of the feature that is enabled for the detector.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::FeatureStatus> {
        &self.status
    }
    /// <p>The timestamp at which the feature object was updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp at which the feature object was updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The timestamp at which the feature object was updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// Appends an item to `additional_configuration`.
    ///
    /// To override the contents of this collection use [`set_additional_configuration`](Self::set_additional_configuration).
    ///
    /// <p>Indicates the additional configuration of the feature that is configured for the member account.</p>
    pub fn additional_configuration(mut self, input: crate::types::MemberAdditionalConfigurationResult) -> Self {
        let mut v = self.additional_configuration.unwrap_or_default();
        v.push(input);
        self.additional_configuration = ::std::option::Option::Some(v);
        self
    }
    /// <p>Indicates the additional configuration of the feature that is configured for the member account.</p>
    pub fn set_additional_configuration(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::MemberAdditionalConfigurationResult>>,
    ) -> Self {
        self.additional_configuration = input;
        self
    }
    /// <p>Indicates the additional configuration of the feature that is configured for the member account.</p>
    pub fn get_additional_configuration(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MemberAdditionalConfigurationResult>> {
        &self.additional_configuration
    }
    /// Consumes the builder and constructs a [`MemberFeaturesConfigurationResult`](crate::types::MemberFeaturesConfigurationResult).
    pub fn build(self) -> crate::types::MemberFeaturesConfigurationResult {
        crate::types::MemberFeaturesConfigurationResult {
            name: self.name,
            status: self.status,
            updated_at: self.updated_at,
            additional_configuration: self.additional_configuration,
        }
    }
}
