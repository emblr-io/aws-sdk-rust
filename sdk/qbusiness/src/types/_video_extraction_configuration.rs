// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration settings for video content extraction and processing.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VideoExtractionConfiguration {
    /// <p>The status of video extraction (ENABLED or DISABLED) for processing video content from files.</p>
    pub video_extraction_status: crate::types::VideoExtractionStatus,
}
impl VideoExtractionConfiguration {
    /// <p>The status of video extraction (ENABLED or DISABLED) for processing video content from files.</p>
    pub fn video_extraction_status(&self) -> &crate::types::VideoExtractionStatus {
        &self.video_extraction_status
    }
}
impl VideoExtractionConfiguration {
    /// Creates a new builder-style object to manufacture [`VideoExtractionConfiguration`](crate::types::VideoExtractionConfiguration).
    pub fn builder() -> crate::types::builders::VideoExtractionConfigurationBuilder {
        crate::types::builders::VideoExtractionConfigurationBuilder::default()
    }
}

/// A builder for [`VideoExtractionConfiguration`](crate::types::VideoExtractionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VideoExtractionConfigurationBuilder {
    pub(crate) video_extraction_status: ::std::option::Option<crate::types::VideoExtractionStatus>,
}
impl VideoExtractionConfigurationBuilder {
    /// <p>The status of video extraction (ENABLED or DISABLED) for processing video content from files.</p>
    /// This field is required.
    pub fn video_extraction_status(mut self, input: crate::types::VideoExtractionStatus) -> Self {
        self.video_extraction_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of video extraction (ENABLED or DISABLED) for processing video content from files.</p>
    pub fn set_video_extraction_status(mut self, input: ::std::option::Option<crate::types::VideoExtractionStatus>) -> Self {
        self.video_extraction_status = input;
        self
    }
    /// <p>The status of video extraction (ENABLED or DISABLED) for processing video content from files.</p>
    pub fn get_video_extraction_status(&self) -> &::std::option::Option<crate::types::VideoExtractionStatus> {
        &self.video_extraction_status
    }
    /// Consumes the builder and constructs a [`VideoExtractionConfiguration`](crate::types::VideoExtractionConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`video_extraction_status`](crate::types::builders::VideoExtractionConfigurationBuilder::video_extraction_status)
    pub fn build(self) -> ::std::result::Result<crate::types::VideoExtractionConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VideoExtractionConfiguration {
            video_extraction_status: self.video_extraction_status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "video_extraction_status",
                    "video_extraction_status was not specified but it is required when building VideoExtractionConfiguration",
                )
            })?,
        })
    }
}
