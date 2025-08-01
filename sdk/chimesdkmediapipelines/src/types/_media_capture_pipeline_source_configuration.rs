// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The source configuration object of a media capture pipeline.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct MediaCapturePipelineSourceConfiguration {
    /// <p>The media pipeline ARN in the configuration object of a media capture pipeline.</p>
    pub media_pipeline_arn: ::std::string::String,
    /// <p>The meeting configuration settings in a media capture pipeline configuration object.</p>
    pub chime_sdk_meeting_configuration: ::std::option::Option<crate::types::ChimeSdkMeetingConcatenationConfiguration>,
}
impl MediaCapturePipelineSourceConfiguration {
    /// <p>The media pipeline ARN in the configuration object of a media capture pipeline.</p>
    pub fn media_pipeline_arn(&self) -> &str {
        use std::ops::Deref;
        self.media_pipeline_arn.deref()
    }
    /// <p>The meeting configuration settings in a media capture pipeline configuration object.</p>
    pub fn chime_sdk_meeting_configuration(&self) -> ::std::option::Option<&crate::types::ChimeSdkMeetingConcatenationConfiguration> {
        self.chime_sdk_meeting_configuration.as_ref()
    }
}
impl ::std::fmt::Debug for MediaCapturePipelineSourceConfiguration {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("MediaCapturePipelineSourceConfiguration");
        formatter.field("media_pipeline_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("chime_sdk_meeting_configuration", &self.chime_sdk_meeting_configuration);
        formatter.finish()
    }
}
impl MediaCapturePipelineSourceConfiguration {
    /// Creates a new builder-style object to manufacture [`MediaCapturePipelineSourceConfiguration`](crate::types::MediaCapturePipelineSourceConfiguration).
    pub fn builder() -> crate::types::builders::MediaCapturePipelineSourceConfigurationBuilder {
        crate::types::builders::MediaCapturePipelineSourceConfigurationBuilder::default()
    }
}

/// A builder for [`MediaCapturePipelineSourceConfiguration`](crate::types::MediaCapturePipelineSourceConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct MediaCapturePipelineSourceConfigurationBuilder {
    pub(crate) media_pipeline_arn: ::std::option::Option<::std::string::String>,
    pub(crate) chime_sdk_meeting_configuration: ::std::option::Option<crate::types::ChimeSdkMeetingConcatenationConfiguration>,
}
impl MediaCapturePipelineSourceConfigurationBuilder {
    /// <p>The media pipeline ARN in the configuration object of a media capture pipeline.</p>
    /// This field is required.
    pub fn media_pipeline_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.media_pipeline_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The media pipeline ARN in the configuration object of a media capture pipeline.</p>
    pub fn set_media_pipeline_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.media_pipeline_arn = input;
        self
    }
    /// <p>The media pipeline ARN in the configuration object of a media capture pipeline.</p>
    pub fn get_media_pipeline_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.media_pipeline_arn
    }
    /// <p>The meeting configuration settings in a media capture pipeline configuration object.</p>
    /// This field is required.
    pub fn chime_sdk_meeting_configuration(mut self, input: crate::types::ChimeSdkMeetingConcatenationConfiguration) -> Self {
        self.chime_sdk_meeting_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The meeting configuration settings in a media capture pipeline configuration object.</p>
    pub fn set_chime_sdk_meeting_configuration(
        mut self,
        input: ::std::option::Option<crate::types::ChimeSdkMeetingConcatenationConfiguration>,
    ) -> Self {
        self.chime_sdk_meeting_configuration = input;
        self
    }
    /// <p>The meeting configuration settings in a media capture pipeline configuration object.</p>
    pub fn get_chime_sdk_meeting_configuration(&self) -> &::std::option::Option<crate::types::ChimeSdkMeetingConcatenationConfiguration> {
        &self.chime_sdk_meeting_configuration
    }
    /// Consumes the builder and constructs a [`MediaCapturePipelineSourceConfiguration`](crate::types::MediaCapturePipelineSourceConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`media_pipeline_arn`](crate::types::builders::MediaCapturePipelineSourceConfigurationBuilder::media_pipeline_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::MediaCapturePipelineSourceConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::MediaCapturePipelineSourceConfiguration {
            media_pipeline_arn: self.media_pipeline_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "media_pipeline_arn",
                    "media_pipeline_arn was not specified but it is required when building MediaCapturePipelineSourceConfiguration",
                )
            })?,
            chime_sdk_meeting_configuration: self.chime_sdk_meeting_configuration,
        })
    }
}
impl ::std::fmt::Debug for MediaCapturePipelineSourceConfigurationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("MediaCapturePipelineSourceConfigurationBuilder");
        formatter.field("media_pipeline_arn", &"*** Sensitive Data Redacted ***");
        formatter.field("chime_sdk_meeting_configuration", &self.chime_sdk_meeting_configuration);
        formatter.finish()
    }
}
