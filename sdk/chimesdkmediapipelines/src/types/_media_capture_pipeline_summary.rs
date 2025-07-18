// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary data of a media capture pipeline.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MediaCapturePipelineSummary {
    /// <p>The ID of the media pipeline in the summary.</p>
    pub media_pipeline_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the media pipeline in the summary.</p>
    pub media_pipeline_arn: ::std::option::Option<::std::string::String>,
}
impl MediaCapturePipelineSummary {
    /// <p>The ID of the media pipeline in the summary.</p>
    pub fn media_pipeline_id(&self) -> ::std::option::Option<&str> {
        self.media_pipeline_id.as_deref()
    }
    /// <p>The ARN of the media pipeline in the summary.</p>
    pub fn media_pipeline_arn(&self) -> ::std::option::Option<&str> {
        self.media_pipeline_arn.as_deref()
    }
}
impl MediaCapturePipelineSummary {
    /// Creates a new builder-style object to manufacture [`MediaCapturePipelineSummary`](crate::types::MediaCapturePipelineSummary).
    pub fn builder() -> crate::types::builders::MediaCapturePipelineSummaryBuilder {
        crate::types::builders::MediaCapturePipelineSummaryBuilder::default()
    }
}

/// A builder for [`MediaCapturePipelineSummary`](crate::types::MediaCapturePipelineSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MediaCapturePipelineSummaryBuilder {
    pub(crate) media_pipeline_id: ::std::option::Option<::std::string::String>,
    pub(crate) media_pipeline_arn: ::std::option::Option<::std::string::String>,
}
impl MediaCapturePipelineSummaryBuilder {
    /// <p>The ID of the media pipeline in the summary.</p>
    pub fn media_pipeline_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.media_pipeline_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the media pipeline in the summary.</p>
    pub fn set_media_pipeline_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.media_pipeline_id = input;
        self
    }
    /// <p>The ID of the media pipeline in the summary.</p>
    pub fn get_media_pipeline_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.media_pipeline_id
    }
    /// <p>The ARN of the media pipeline in the summary.</p>
    pub fn media_pipeline_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.media_pipeline_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the media pipeline in the summary.</p>
    pub fn set_media_pipeline_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.media_pipeline_arn = input;
        self
    }
    /// <p>The ARN of the media pipeline in the summary.</p>
    pub fn get_media_pipeline_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.media_pipeline_arn
    }
    /// Consumes the builder and constructs a [`MediaCapturePipelineSummary`](crate::types::MediaCapturePipelineSummary).
    pub fn build(self) -> crate::types::MediaCapturePipelineSummary {
        crate::types::MediaCapturePipelineSummary {
            media_pipeline_id: self.media_pipeline_id,
            media_pipeline_arn: self.media_pipeline_arn,
        }
    }
}
