// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Video asset processing configuration
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VideoAssetProcessingConfiguration {
    /// Delimits the segment of the input that will be processed
    pub segment_configuration: ::std::option::Option<crate::types::VideoSegmentConfiguration>,
}
impl VideoAssetProcessingConfiguration {
    /// Delimits the segment of the input that will be processed
    pub fn segment_configuration(&self) -> ::std::option::Option<&crate::types::VideoSegmentConfiguration> {
        self.segment_configuration.as_ref()
    }
}
impl VideoAssetProcessingConfiguration {
    /// Creates a new builder-style object to manufacture [`VideoAssetProcessingConfiguration`](crate::types::VideoAssetProcessingConfiguration).
    pub fn builder() -> crate::types::builders::VideoAssetProcessingConfigurationBuilder {
        crate::types::builders::VideoAssetProcessingConfigurationBuilder::default()
    }
}

/// A builder for [`VideoAssetProcessingConfiguration`](crate::types::VideoAssetProcessingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VideoAssetProcessingConfigurationBuilder {
    pub(crate) segment_configuration: ::std::option::Option<crate::types::VideoSegmentConfiguration>,
}
impl VideoAssetProcessingConfigurationBuilder {
    /// Delimits the segment of the input that will be processed
    pub fn segment_configuration(mut self, input: crate::types::VideoSegmentConfiguration) -> Self {
        self.segment_configuration = ::std::option::Option::Some(input);
        self
    }
    /// Delimits the segment of the input that will be processed
    pub fn set_segment_configuration(mut self, input: ::std::option::Option<crate::types::VideoSegmentConfiguration>) -> Self {
        self.segment_configuration = input;
        self
    }
    /// Delimits the segment of the input that will be processed
    pub fn get_segment_configuration(&self) -> &::std::option::Option<crate::types::VideoSegmentConfiguration> {
        &self.segment_configuration
    }
    /// Consumes the builder and constructs a [`VideoAssetProcessingConfiguration`](crate::types::VideoAssetProcessingConfiguration).
    pub fn build(self) -> crate::types::VideoAssetProcessingConfiguration {
        crate::types::VideoAssetProcessingConfiguration {
            segment_configuration: self.segment_configuration,
        }
    }
}
