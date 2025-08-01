// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes which features are activated for the detector.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsGuardDutyDetectorFeaturesDetails {
    /// <p>Indicates the name of the feature that is activated for the detector.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the status of the feature that is activated for the detector.</p>
    pub status: ::std::option::Option<::std::string::String>,
}
impl AwsGuardDutyDetectorFeaturesDetails {
    /// <p>Indicates the name of the feature that is activated for the detector.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Indicates the status of the feature that is activated for the detector.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
}
impl AwsGuardDutyDetectorFeaturesDetails {
    /// Creates a new builder-style object to manufacture [`AwsGuardDutyDetectorFeaturesDetails`](crate::types::AwsGuardDutyDetectorFeaturesDetails).
    pub fn builder() -> crate::types::builders::AwsGuardDutyDetectorFeaturesDetailsBuilder {
        crate::types::builders::AwsGuardDutyDetectorFeaturesDetailsBuilder::default()
    }
}

/// A builder for [`AwsGuardDutyDetectorFeaturesDetails`](crate::types::AwsGuardDutyDetectorFeaturesDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsGuardDutyDetectorFeaturesDetailsBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
}
impl AwsGuardDutyDetectorFeaturesDetailsBuilder {
    /// <p>Indicates the name of the feature that is activated for the detector.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the name of the feature that is activated for the detector.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>Indicates the name of the feature that is activated for the detector.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Indicates the status of the feature that is activated for the detector.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the status of the feature that is activated for the detector.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>Indicates the status of the feature that is activated for the detector.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// Consumes the builder and constructs a [`AwsGuardDutyDetectorFeaturesDetails`](crate::types::AwsGuardDutyDetectorFeaturesDetails).
    pub fn build(self) -> crate::types::AwsGuardDutyDetectorFeaturesDetails {
        crate::types::AwsGuardDutyDetectorFeaturesDetails {
            name: self.name,
            status: self.status,
        }
    }
}
