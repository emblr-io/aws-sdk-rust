// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The runtime configuration settings for the Kinesis video stream source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct KinesisVideoStreamSourceRuntimeConfiguration {
    /// <p>The streams in the source runtime configuration of a Kinesis video stream.</p>
    pub streams: ::std::vec::Vec<crate::types::StreamConfiguration>,
    /// <p>Specifies the encoding of your input audio. Supported format: PCM (only signed 16-bit little-endian audio formats, which does not include WAV)</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/how-input.html#how-input-audio">Media formats</a> in the <i>Amazon Transcribe Developer Guide</i>.</p>
    pub media_encoding: crate::types::MediaEncoding,
    /// <p>The sample rate of the input audio (in hertz). Low-quality audio, such as telephone audio, is typically around 8,000 Hz. High-quality audio typically ranges from 16,000 Hz to 48,000 Hz. Note that the sample rate you specify must match that of your audio.</p>
    /// <p>Valid Range: Minimum value of 8000. Maximum value of 48000.</p>
    pub media_sample_rate: i32,
}
impl KinesisVideoStreamSourceRuntimeConfiguration {
    /// <p>The streams in the source runtime configuration of a Kinesis video stream.</p>
    pub fn streams(&self) -> &[crate::types::StreamConfiguration] {
        use std::ops::Deref;
        self.streams.deref()
    }
    /// <p>Specifies the encoding of your input audio. Supported format: PCM (only signed 16-bit little-endian audio formats, which does not include WAV)</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/how-input.html#how-input-audio">Media formats</a> in the <i>Amazon Transcribe Developer Guide</i>.</p>
    pub fn media_encoding(&self) -> &crate::types::MediaEncoding {
        &self.media_encoding
    }
    /// <p>The sample rate of the input audio (in hertz). Low-quality audio, such as telephone audio, is typically around 8,000 Hz. High-quality audio typically ranges from 16,000 Hz to 48,000 Hz. Note that the sample rate you specify must match that of your audio.</p>
    /// <p>Valid Range: Minimum value of 8000. Maximum value of 48000.</p>
    pub fn media_sample_rate(&self) -> i32 {
        self.media_sample_rate
    }
}
impl KinesisVideoStreamSourceRuntimeConfiguration {
    /// Creates a new builder-style object to manufacture [`KinesisVideoStreamSourceRuntimeConfiguration`](crate::types::KinesisVideoStreamSourceRuntimeConfiguration).
    pub fn builder() -> crate::types::builders::KinesisVideoStreamSourceRuntimeConfigurationBuilder {
        crate::types::builders::KinesisVideoStreamSourceRuntimeConfigurationBuilder::default()
    }
}

/// A builder for [`KinesisVideoStreamSourceRuntimeConfiguration`](crate::types::KinesisVideoStreamSourceRuntimeConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct KinesisVideoStreamSourceRuntimeConfigurationBuilder {
    pub(crate) streams: ::std::option::Option<::std::vec::Vec<crate::types::StreamConfiguration>>,
    pub(crate) media_encoding: ::std::option::Option<crate::types::MediaEncoding>,
    pub(crate) media_sample_rate: ::std::option::Option<i32>,
}
impl KinesisVideoStreamSourceRuntimeConfigurationBuilder {
    /// Appends an item to `streams`.
    ///
    /// To override the contents of this collection use [`set_streams`](Self::set_streams).
    ///
    /// <p>The streams in the source runtime configuration of a Kinesis video stream.</p>
    pub fn streams(mut self, input: crate::types::StreamConfiguration) -> Self {
        let mut v = self.streams.unwrap_or_default();
        v.push(input);
        self.streams = ::std::option::Option::Some(v);
        self
    }
    /// <p>The streams in the source runtime configuration of a Kinesis video stream.</p>
    pub fn set_streams(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StreamConfiguration>>) -> Self {
        self.streams = input;
        self
    }
    /// <p>The streams in the source runtime configuration of a Kinesis video stream.</p>
    pub fn get_streams(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StreamConfiguration>> {
        &self.streams
    }
    /// <p>Specifies the encoding of your input audio. Supported format: PCM (only signed 16-bit little-endian audio formats, which does not include WAV)</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/how-input.html#how-input-audio">Media formats</a> in the <i>Amazon Transcribe Developer Guide</i>.</p>
    /// This field is required.
    pub fn media_encoding(mut self, input: crate::types::MediaEncoding) -> Self {
        self.media_encoding = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the encoding of your input audio. Supported format: PCM (only signed 16-bit little-endian audio formats, which does not include WAV)</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/how-input.html#how-input-audio">Media formats</a> in the <i>Amazon Transcribe Developer Guide</i>.</p>
    pub fn set_media_encoding(mut self, input: ::std::option::Option<crate::types::MediaEncoding>) -> Self {
        self.media_encoding = input;
        self
    }
    /// <p>Specifies the encoding of your input audio. Supported format: PCM (only signed 16-bit little-endian audio formats, which does not include WAV)</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/transcribe/latest/dg/how-input.html#how-input-audio">Media formats</a> in the <i>Amazon Transcribe Developer Guide</i>.</p>
    pub fn get_media_encoding(&self) -> &::std::option::Option<crate::types::MediaEncoding> {
        &self.media_encoding
    }
    /// <p>The sample rate of the input audio (in hertz). Low-quality audio, such as telephone audio, is typically around 8,000 Hz. High-quality audio typically ranges from 16,000 Hz to 48,000 Hz. Note that the sample rate you specify must match that of your audio.</p>
    /// <p>Valid Range: Minimum value of 8000. Maximum value of 48000.</p>
    /// This field is required.
    pub fn media_sample_rate(mut self, input: i32) -> Self {
        self.media_sample_rate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sample rate of the input audio (in hertz). Low-quality audio, such as telephone audio, is typically around 8,000 Hz. High-quality audio typically ranges from 16,000 Hz to 48,000 Hz. Note that the sample rate you specify must match that of your audio.</p>
    /// <p>Valid Range: Minimum value of 8000. Maximum value of 48000.</p>
    pub fn set_media_sample_rate(mut self, input: ::std::option::Option<i32>) -> Self {
        self.media_sample_rate = input;
        self
    }
    /// <p>The sample rate of the input audio (in hertz). Low-quality audio, such as telephone audio, is typically around 8,000 Hz. High-quality audio typically ranges from 16,000 Hz to 48,000 Hz. Note that the sample rate you specify must match that of your audio.</p>
    /// <p>Valid Range: Minimum value of 8000. Maximum value of 48000.</p>
    pub fn get_media_sample_rate(&self) -> &::std::option::Option<i32> {
        &self.media_sample_rate
    }
    /// Consumes the builder and constructs a [`KinesisVideoStreamSourceRuntimeConfiguration`](crate::types::KinesisVideoStreamSourceRuntimeConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`streams`](crate::types::builders::KinesisVideoStreamSourceRuntimeConfigurationBuilder::streams)
    /// - [`media_encoding`](crate::types::builders::KinesisVideoStreamSourceRuntimeConfigurationBuilder::media_encoding)
    /// - [`media_sample_rate`](crate::types::builders::KinesisVideoStreamSourceRuntimeConfigurationBuilder::media_sample_rate)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::KinesisVideoStreamSourceRuntimeConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::KinesisVideoStreamSourceRuntimeConfiguration {
            streams: self.streams.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "streams",
                    "streams was not specified but it is required when building KinesisVideoStreamSourceRuntimeConfiguration",
                )
            })?,
            media_encoding: self.media_encoding.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "media_encoding",
                    "media_encoding was not specified but it is required when building KinesisVideoStreamSourceRuntimeConfiguration",
                )
            })?,
            media_sample_rate: self.media_sample_rate.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "media_sample_rate",
                    "media_sample_rate was not specified but it is required when building KinesisVideoStreamSourceRuntimeConfiguration",
                )
            })?,
        })
    }
}
