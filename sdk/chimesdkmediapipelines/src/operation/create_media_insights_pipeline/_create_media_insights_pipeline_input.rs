// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateMediaInsightsPipelineInput {
    /// <p>The ARN of the pipeline's configuration.</p>
    pub media_insights_pipeline_configuration_arn: ::std::option::Option<::std::string::String>,
    /// <p>The runtime configuration for the Kinesis video stream source of the media insights pipeline.</p>
    pub kinesis_video_stream_source_runtime_configuration: ::std::option::Option<crate::types::KinesisVideoStreamSourceRuntimeConfiguration>,
    /// <p>The runtime metadata for the media insights pipeline. Consists of a key-value map of strings.</p>
    pub media_insights_runtime_metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The runtime configuration for the Kinesis video recording stream source.</p>
    pub kinesis_video_stream_recording_source_runtime_configuration:
        ::std::option::Option<crate::types::KinesisVideoStreamRecordingSourceRuntimeConfiguration>,
    /// <p>The runtime configuration for the S3 recording sink. If specified, the settings in this structure override any settings in <code>S3RecordingSinkConfiguration</code>.</p>
    pub s3_recording_sink_runtime_configuration: ::std::option::Option<crate::types::S3RecordingSinkRuntimeConfiguration>,
    /// <p>The tags assigned to the media insights pipeline.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The unique identifier for the media insights pipeline request.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateMediaInsightsPipelineInput {
    /// <p>The ARN of the pipeline's configuration.</p>
    pub fn media_insights_pipeline_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.media_insights_pipeline_configuration_arn.as_deref()
    }
    /// <p>The runtime configuration for the Kinesis video stream source of the media insights pipeline.</p>
    pub fn kinesis_video_stream_source_runtime_configuration(
        &self,
    ) -> ::std::option::Option<&crate::types::KinesisVideoStreamSourceRuntimeConfiguration> {
        self.kinesis_video_stream_source_runtime_configuration.as_ref()
    }
    /// <p>The runtime metadata for the media insights pipeline. Consists of a key-value map of strings.</p>
    pub fn media_insights_runtime_metadata(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.media_insights_runtime_metadata.as_ref()
    }
    /// <p>The runtime configuration for the Kinesis video recording stream source.</p>
    pub fn kinesis_video_stream_recording_source_runtime_configuration(
        &self,
    ) -> ::std::option::Option<&crate::types::KinesisVideoStreamRecordingSourceRuntimeConfiguration> {
        self.kinesis_video_stream_recording_source_runtime_configuration.as_ref()
    }
    /// <p>The runtime configuration for the S3 recording sink. If specified, the settings in this structure override any settings in <code>S3RecordingSinkConfiguration</code>.</p>
    pub fn s3_recording_sink_runtime_configuration(&self) -> ::std::option::Option<&crate::types::S3RecordingSinkRuntimeConfiguration> {
        self.s3_recording_sink_runtime_configuration.as_ref()
    }
    /// <p>The tags assigned to the media insights pipeline.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The unique identifier for the media insights pipeline request.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl ::std::fmt::Debug for CreateMediaInsightsPipelineInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateMediaInsightsPipelineInput");
        formatter.field("media_insights_pipeline_configuration_arn", &"*** Sensitive Data Redacted ***");
        formatter.field(
            "kinesis_video_stream_source_runtime_configuration",
            &self.kinesis_video_stream_source_runtime_configuration,
        );
        formatter.field("media_insights_runtime_metadata", &"*** Sensitive Data Redacted ***");
        formatter.field(
            "kinesis_video_stream_recording_source_runtime_configuration",
            &self.kinesis_video_stream_recording_source_runtime_configuration,
        );
        formatter.field("s3_recording_sink_runtime_configuration", &self.s3_recording_sink_runtime_configuration);
        formatter.field("tags", &self.tags);
        formatter.field("client_request_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl CreateMediaInsightsPipelineInput {
    /// Creates a new builder-style object to manufacture [`CreateMediaInsightsPipelineInput`](crate::operation::create_media_insights_pipeline::CreateMediaInsightsPipelineInput).
    pub fn builder() -> crate::operation::create_media_insights_pipeline::builders::CreateMediaInsightsPipelineInputBuilder {
        crate::operation::create_media_insights_pipeline::builders::CreateMediaInsightsPipelineInputBuilder::default()
    }
}

/// A builder for [`CreateMediaInsightsPipelineInput`](crate::operation::create_media_insights_pipeline::CreateMediaInsightsPipelineInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateMediaInsightsPipelineInputBuilder {
    pub(crate) media_insights_pipeline_configuration_arn: ::std::option::Option<::std::string::String>,
    pub(crate) kinesis_video_stream_source_runtime_configuration: ::std::option::Option<crate::types::KinesisVideoStreamSourceRuntimeConfiguration>,
    pub(crate) media_insights_runtime_metadata: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) kinesis_video_stream_recording_source_runtime_configuration:
        ::std::option::Option<crate::types::KinesisVideoStreamRecordingSourceRuntimeConfiguration>,
    pub(crate) s3_recording_sink_runtime_configuration: ::std::option::Option<crate::types::S3RecordingSinkRuntimeConfiguration>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl CreateMediaInsightsPipelineInputBuilder {
    /// <p>The ARN of the pipeline's configuration.</p>
    /// This field is required.
    pub fn media_insights_pipeline_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.media_insights_pipeline_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the pipeline's configuration.</p>
    pub fn set_media_insights_pipeline_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.media_insights_pipeline_configuration_arn = input;
        self
    }
    /// <p>The ARN of the pipeline's configuration.</p>
    pub fn get_media_insights_pipeline_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.media_insights_pipeline_configuration_arn
    }
    /// <p>The runtime configuration for the Kinesis video stream source of the media insights pipeline.</p>
    pub fn kinesis_video_stream_source_runtime_configuration(mut self, input: crate::types::KinesisVideoStreamSourceRuntimeConfiguration) -> Self {
        self.kinesis_video_stream_source_runtime_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The runtime configuration for the Kinesis video stream source of the media insights pipeline.</p>
    pub fn set_kinesis_video_stream_source_runtime_configuration(
        mut self,
        input: ::std::option::Option<crate::types::KinesisVideoStreamSourceRuntimeConfiguration>,
    ) -> Self {
        self.kinesis_video_stream_source_runtime_configuration = input;
        self
    }
    /// <p>The runtime configuration for the Kinesis video stream source of the media insights pipeline.</p>
    pub fn get_kinesis_video_stream_source_runtime_configuration(
        &self,
    ) -> &::std::option::Option<crate::types::KinesisVideoStreamSourceRuntimeConfiguration> {
        &self.kinesis_video_stream_source_runtime_configuration
    }
    /// Adds a key-value pair to `media_insights_runtime_metadata`.
    ///
    /// To override the contents of this collection use [`set_media_insights_runtime_metadata`](Self::set_media_insights_runtime_metadata).
    ///
    /// <p>The runtime metadata for the media insights pipeline. Consists of a key-value map of strings.</p>
    pub fn media_insights_runtime_metadata(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.media_insights_runtime_metadata.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.media_insights_runtime_metadata = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The runtime metadata for the media insights pipeline. Consists of a key-value map of strings.</p>
    pub fn set_media_insights_runtime_metadata(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.media_insights_runtime_metadata = input;
        self
    }
    /// <p>The runtime metadata for the media insights pipeline. Consists of a key-value map of strings.</p>
    pub fn get_media_insights_runtime_metadata(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.media_insights_runtime_metadata
    }
    /// <p>The runtime configuration for the Kinesis video recording stream source.</p>
    pub fn kinesis_video_stream_recording_source_runtime_configuration(
        mut self,
        input: crate::types::KinesisVideoStreamRecordingSourceRuntimeConfiguration,
    ) -> Self {
        self.kinesis_video_stream_recording_source_runtime_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The runtime configuration for the Kinesis video recording stream source.</p>
    pub fn set_kinesis_video_stream_recording_source_runtime_configuration(
        mut self,
        input: ::std::option::Option<crate::types::KinesisVideoStreamRecordingSourceRuntimeConfiguration>,
    ) -> Self {
        self.kinesis_video_stream_recording_source_runtime_configuration = input;
        self
    }
    /// <p>The runtime configuration for the Kinesis video recording stream source.</p>
    pub fn get_kinesis_video_stream_recording_source_runtime_configuration(
        &self,
    ) -> &::std::option::Option<crate::types::KinesisVideoStreamRecordingSourceRuntimeConfiguration> {
        &self.kinesis_video_stream_recording_source_runtime_configuration
    }
    /// <p>The runtime configuration for the S3 recording sink. If specified, the settings in this structure override any settings in <code>S3RecordingSinkConfiguration</code>.</p>
    pub fn s3_recording_sink_runtime_configuration(mut self, input: crate::types::S3RecordingSinkRuntimeConfiguration) -> Self {
        self.s3_recording_sink_runtime_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The runtime configuration for the S3 recording sink. If specified, the settings in this structure override any settings in <code>S3RecordingSinkConfiguration</code>.</p>
    pub fn set_s3_recording_sink_runtime_configuration(
        mut self,
        input: ::std::option::Option<crate::types::S3RecordingSinkRuntimeConfiguration>,
    ) -> Self {
        self.s3_recording_sink_runtime_configuration = input;
        self
    }
    /// <p>The runtime configuration for the S3 recording sink. If specified, the settings in this structure override any settings in <code>S3RecordingSinkConfiguration</code>.</p>
    pub fn get_s3_recording_sink_runtime_configuration(&self) -> &::std::option::Option<crate::types::S3RecordingSinkRuntimeConfiguration> {
        &self.s3_recording_sink_runtime_configuration
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags assigned to the media insights pipeline.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags assigned to the media insights pipeline.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags assigned to the media insights pipeline.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The unique identifier for the media insights pipeline request.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the media insights pipeline request.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>The unique identifier for the media insights pipeline request.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`CreateMediaInsightsPipelineInput`](crate::operation::create_media_insights_pipeline::CreateMediaInsightsPipelineInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_media_insights_pipeline::CreateMediaInsightsPipelineInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_media_insights_pipeline::CreateMediaInsightsPipelineInput {
            media_insights_pipeline_configuration_arn: self.media_insights_pipeline_configuration_arn,
            kinesis_video_stream_source_runtime_configuration: self.kinesis_video_stream_source_runtime_configuration,
            media_insights_runtime_metadata: self.media_insights_runtime_metadata,
            kinesis_video_stream_recording_source_runtime_configuration: self.kinesis_video_stream_recording_source_runtime_configuration,
            s3_recording_sink_runtime_configuration: self.s3_recording_sink_runtime_configuration,
            tags: self.tags,
            client_request_token: self.client_request_token,
        })
    }
}
impl ::std::fmt::Debug for CreateMediaInsightsPipelineInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateMediaInsightsPipelineInputBuilder");
        formatter.field("media_insights_pipeline_configuration_arn", &"*** Sensitive Data Redacted ***");
        formatter.field(
            "kinesis_video_stream_source_runtime_configuration",
            &self.kinesis_video_stream_source_runtime_configuration,
        );
        formatter.field("media_insights_runtime_metadata", &"*** Sensitive Data Redacted ***");
        formatter.field(
            "kinesis_video_stream_recording_source_runtime_configuration",
            &self.kinesis_video_stream_recording_source_runtime_configuration,
        );
        formatter.field("s3_recording_sink_runtime_configuration", &self.s3_recording_sink_runtime_configuration);
        formatter.field("tags", &self.tags);
        formatter.field("client_request_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
