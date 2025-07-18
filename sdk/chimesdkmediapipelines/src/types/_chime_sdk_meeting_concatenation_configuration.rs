// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration object of the Amazon Chime SDK meeting concatenation for a specified media pipeline.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChimeSdkMeetingConcatenationConfiguration {
    /// <p>The configuration for the artifacts in an Amazon Chime SDK meeting concatenation.</p>
    pub artifacts_configuration: ::std::option::Option<crate::types::ArtifactsConcatenationConfiguration>,
}
impl ChimeSdkMeetingConcatenationConfiguration {
    /// <p>The configuration for the artifacts in an Amazon Chime SDK meeting concatenation.</p>
    pub fn artifacts_configuration(&self) -> ::std::option::Option<&crate::types::ArtifactsConcatenationConfiguration> {
        self.artifacts_configuration.as_ref()
    }
}
impl ChimeSdkMeetingConcatenationConfiguration {
    /// Creates a new builder-style object to manufacture [`ChimeSdkMeetingConcatenationConfiguration`](crate::types::ChimeSdkMeetingConcatenationConfiguration).
    pub fn builder() -> crate::types::builders::ChimeSdkMeetingConcatenationConfigurationBuilder {
        crate::types::builders::ChimeSdkMeetingConcatenationConfigurationBuilder::default()
    }
}

/// A builder for [`ChimeSdkMeetingConcatenationConfiguration`](crate::types::ChimeSdkMeetingConcatenationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChimeSdkMeetingConcatenationConfigurationBuilder {
    pub(crate) artifacts_configuration: ::std::option::Option<crate::types::ArtifactsConcatenationConfiguration>,
}
impl ChimeSdkMeetingConcatenationConfigurationBuilder {
    /// <p>The configuration for the artifacts in an Amazon Chime SDK meeting concatenation.</p>
    /// This field is required.
    pub fn artifacts_configuration(mut self, input: crate::types::ArtifactsConcatenationConfiguration) -> Self {
        self.artifacts_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for the artifacts in an Amazon Chime SDK meeting concatenation.</p>
    pub fn set_artifacts_configuration(mut self, input: ::std::option::Option<crate::types::ArtifactsConcatenationConfiguration>) -> Self {
        self.artifacts_configuration = input;
        self
    }
    /// <p>The configuration for the artifacts in an Amazon Chime SDK meeting concatenation.</p>
    pub fn get_artifacts_configuration(&self) -> &::std::option::Option<crate::types::ArtifactsConcatenationConfiguration> {
        &self.artifacts_configuration
    }
    /// Consumes the builder and constructs a [`ChimeSdkMeetingConcatenationConfiguration`](crate::types::ChimeSdkMeetingConcatenationConfiguration).
    pub fn build(self) -> crate::types::ChimeSdkMeetingConcatenationConfiguration {
        crate::types::ChimeSdkMeetingConcatenationConfiguration {
            artifacts_configuration: self.artifacts_configuration,
        }
    }
}
