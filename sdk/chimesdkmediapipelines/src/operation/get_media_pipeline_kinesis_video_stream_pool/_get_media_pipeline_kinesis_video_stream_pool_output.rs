// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetMediaPipelineKinesisVideoStreamPoolOutput {
    /// <p>The video stream pool configuration object.</p>
    pub kinesis_video_stream_pool_configuration: ::std::option::Option<crate::types::KinesisVideoStreamPoolConfiguration>,
    _request_id: Option<String>,
}
impl GetMediaPipelineKinesisVideoStreamPoolOutput {
    /// <p>The video stream pool configuration object.</p>
    pub fn kinesis_video_stream_pool_configuration(&self) -> ::std::option::Option<&crate::types::KinesisVideoStreamPoolConfiguration> {
        self.kinesis_video_stream_pool_configuration.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetMediaPipelineKinesisVideoStreamPoolOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetMediaPipelineKinesisVideoStreamPoolOutput {
    /// Creates a new builder-style object to manufacture [`GetMediaPipelineKinesisVideoStreamPoolOutput`](crate::operation::get_media_pipeline_kinesis_video_stream_pool::GetMediaPipelineKinesisVideoStreamPoolOutput).
    pub fn builder() -> crate::operation::get_media_pipeline_kinesis_video_stream_pool::builders::GetMediaPipelineKinesisVideoStreamPoolOutputBuilder
    {
        crate::operation::get_media_pipeline_kinesis_video_stream_pool::builders::GetMediaPipelineKinesisVideoStreamPoolOutputBuilder::default()
    }
}

/// A builder for [`GetMediaPipelineKinesisVideoStreamPoolOutput`](crate::operation::get_media_pipeline_kinesis_video_stream_pool::GetMediaPipelineKinesisVideoStreamPoolOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetMediaPipelineKinesisVideoStreamPoolOutputBuilder {
    pub(crate) kinesis_video_stream_pool_configuration: ::std::option::Option<crate::types::KinesisVideoStreamPoolConfiguration>,
    _request_id: Option<String>,
}
impl GetMediaPipelineKinesisVideoStreamPoolOutputBuilder {
    /// <p>The video stream pool configuration object.</p>
    pub fn kinesis_video_stream_pool_configuration(mut self, input: crate::types::KinesisVideoStreamPoolConfiguration) -> Self {
        self.kinesis_video_stream_pool_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The video stream pool configuration object.</p>
    pub fn set_kinesis_video_stream_pool_configuration(
        mut self,
        input: ::std::option::Option<crate::types::KinesisVideoStreamPoolConfiguration>,
    ) -> Self {
        self.kinesis_video_stream_pool_configuration = input;
        self
    }
    /// <p>The video stream pool configuration object.</p>
    pub fn get_kinesis_video_stream_pool_configuration(&self) -> &::std::option::Option<crate::types::KinesisVideoStreamPoolConfiguration> {
        &self.kinesis_video_stream_pool_configuration
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetMediaPipelineKinesisVideoStreamPoolOutput`](crate::operation::get_media_pipeline_kinesis_video_stream_pool::GetMediaPipelineKinesisVideoStreamPoolOutput).
    pub fn build(self) -> crate::operation::get_media_pipeline_kinesis_video_stream_pool::GetMediaPipelineKinesisVideoStreamPoolOutput {
        crate::operation::get_media_pipeline_kinesis_video_stream_pool::GetMediaPipelineKinesisVideoStreamPoolOutput {
            kinesis_video_stream_pool_configuration: self.kinesis_video_stream_pool_configuration,
            _request_id: self._request_id,
        }
    }
}
