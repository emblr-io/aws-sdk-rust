// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartSegmentDetectionInput {
    /// <p>Video file stored in an Amazon S3 bucket. Amazon Rekognition video start operations such as <code>StartLabelDetection</code> use <code>Video</code> to specify a video for analysis. The supported file formats are .mp4, .mov and .avi.</p>
    pub video: ::std::option::Option<crate::types::Video>,
    /// <p>Idempotent token used to identify the start request. If you use the same token with multiple <code>StartSegmentDetection</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidently started more than once.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the Amazon SNS topic to which you want Amazon Rekognition Video to publish the completion status of the segment detection operation. Note that the Amazon SNS topic must have a topic name that begins with <i>AmazonRekognition</i> if you are using the AmazonRekognitionServiceRole permissions policy to access the topic.</p>
    pub notification_channel: ::std::option::Option<crate::types::NotificationChannel>,
    /// <p>An identifier you specify that's returned in the completion notification that's published to your Amazon Simple Notification Service topic. For example, you can use <code>JobTag</code> to group related jobs and identify them in the completion notification.</p>
    pub job_tag: ::std::option::Option<::std::string::String>,
    /// <p>Filters for technical cue or shot detection.</p>
    pub filters: ::std::option::Option<crate::types::StartSegmentDetectionFilters>,
    /// <p>An array of segment types to detect in the video. Valid values are TECHNICAL_CUE and SHOT.</p>
    pub segment_types: ::std::option::Option<::std::vec::Vec<crate::types::SegmentType>>,
}
impl StartSegmentDetectionInput {
    /// <p>Video file stored in an Amazon S3 bucket. Amazon Rekognition video start operations such as <code>StartLabelDetection</code> use <code>Video</code> to specify a video for analysis. The supported file formats are .mp4, .mov and .avi.</p>
    pub fn video(&self) -> ::std::option::Option<&crate::types::Video> {
        self.video.as_ref()
    }
    /// <p>Idempotent token used to identify the start request. If you use the same token with multiple <code>StartSegmentDetection</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidently started more than once.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>The ARN of the Amazon SNS topic to which you want Amazon Rekognition Video to publish the completion status of the segment detection operation. Note that the Amazon SNS topic must have a topic name that begins with <i>AmazonRekognition</i> if you are using the AmazonRekognitionServiceRole permissions policy to access the topic.</p>
    pub fn notification_channel(&self) -> ::std::option::Option<&crate::types::NotificationChannel> {
        self.notification_channel.as_ref()
    }
    /// <p>An identifier you specify that's returned in the completion notification that's published to your Amazon Simple Notification Service topic. For example, you can use <code>JobTag</code> to group related jobs and identify them in the completion notification.</p>
    pub fn job_tag(&self) -> ::std::option::Option<&str> {
        self.job_tag.as_deref()
    }
    /// <p>Filters for technical cue or shot detection.</p>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::StartSegmentDetectionFilters> {
        self.filters.as_ref()
    }
    /// <p>An array of segment types to detect in the video. Valid values are TECHNICAL_CUE and SHOT.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.segment_types.is_none()`.
    pub fn segment_types(&self) -> &[crate::types::SegmentType] {
        self.segment_types.as_deref().unwrap_or_default()
    }
}
impl StartSegmentDetectionInput {
    /// Creates a new builder-style object to manufacture [`StartSegmentDetectionInput`](crate::operation::start_segment_detection::StartSegmentDetectionInput).
    pub fn builder() -> crate::operation::start_segment_detection::builders::StartSegmentDetectionInputBuilder {
        crate::operation::start_segment_detection::builders::StartSegmentDetectionInputBuilder::default()
    }
}

/// A builder for [`StartSegmentDetectionInput`](crate::operation::start_segment_detection::StartSegmentDetectionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartSegmentDetectionInputBuilder {
    pub(crate) video: ::std::option::Option<crate::types::Video>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) notification_channel: ::std::option::Option<crate::types::NotificationChannel>,
    pub(crate) job_tag: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<crate::types::StartSegmentDetectionFilters>,
    pub(crate) segment_types: ::std::option::Option<::std::vec::Vec<crate::types::SegmentType>>,
}
impl StartSegmentDetectionInputBuilder {
    /// <p>Video file stored in an Amazon S3 bucket. Amazon Rekognition video start operations such as <code>StartLabelDetection</code> use <code>Video</code> to specify a video for analysis. The supported file formats are .mp4, .mov and .avi.</p>
    /// This field is required.
    pub fn video(mut self, input: crate::types::Video) -> Self {
        self.video = ::std::option::Option::Some(input);
        self
    }
    /// <p>Video file stored in an Amazon S3 bucket. Amazon Rekognition video start operations such as <code>StartLabelDetection</code> use <code>Video</code> to specify a video for analysis. The supported file formats are .mp4, .mov and .avi.</p>
    pub fn set_video(mut self, input: ::std::option::Option<crate::types::Video>) -> Self {
        self.video = input;
        self
    }
    /// <p>Video file stored in an Amazon S3 bucket. Amazon Rekognition video start operations such as <code>StartLabelDetection</code> use <code>Video</code> to specify a video for analysis. The supported file formats are .mp4, .mov and .avi.</p>
    pub fn get_video(&self) -> &::std::option::Option<crate::types::Video> {
        &self.video
    }
    /// <p>Idempotent token used to identify the start request. If you use the same token with multiple <code>StartSegmentDetection</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidently started more than once.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Idempotent token used to identify the start request. If you use the same token with multiple <code>StartSegmentDetection</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidently started more than once.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>Idempotent token used to identify the start request. If you use the same token with multiple <code>StartSegmentDetection</code> requests, the same <code>JobId</code> is returned. Use <code>ClientRequestToken</code> to prevent the same job from being accidently started more than once.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>The ARN of the Amazon SNS topic to which you want Amazon Rekognition Video to publish the completion status of the segment detection operation. Note that the Amazon SNS topic must have a topic name that begins with <i>AmazonRekognition</i> if you are using the AmazonRekognitionServiceRole permissions policy to access the topic.</p>
    pub fn notification_channel(mut self, input: crate::types::NotificationChannel) -> Self {
        self.notification_channel = ::std::option::Option::Some(input);
        self
    }
    /// <p>The ARN of the Amazon SNS topic to which you want Amazon Rekognition Video to publish the completion status of the segment detection operation. Note that the Amazon SNS topic must have a topic name that begins with <i>AmazonRekognition</i> if you are using the AmazonRekognitionServiceRole permissions policy to access the topic.</p>
    pub fn set_notification_channel(mut self, input: ::std::option::Option<crate::types::NotificationChannel>) -> Self {
        self.notification_channel = input;
        self
    }
    /// <p>The ARN of the Amazon SNS topic to which you want Amazon Rekognition Video to publish the completion status of the segment detection operation. Note that the Amazon SNS topic must have a topic name that begins with <i>AmazonRekognition</i> if you are using the AmazonRekognitionServiceRole permissions policy to access the topic.</p>
    pub fn get_notification_channel(&self) -> &::std::option::Option<crate::types::NotificationChannel> {
        &self.notification_channel
    }
    /// <p>An identifier you specify that's returned in the completion notification that's published to your Amazon Simple Notification Service topic. For example, you can use <code>JobTag</code> to group related jobs and identify them in the completion notification.</p>
    pub fn job_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier you specify that's returned in the completion notification that's published to your Amazon Simple Notification Service topic. For example, you can use <code>JobTag</code> to group related jobs and identify them in the completion notification.</p>
    pub fn set_job_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_tag = input;
        self
    }
    /// <p>An identifier you specify that's returned in the completion notification that's published to your Amazon Simple Notification Service topic. For example, you can use <code>JobTag</code> to group related jobs and identify them in the completion notification.</p>
    pub fn get_job_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_tag
    }
    /// <p>Filters for technical cue or shot detection.</p>
    pub fn filters(mut self, input: crate::types::StartSegmentDetectionFilters) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters for technical cue or shot detection.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::StartSegmentDetectionFilters>) -> Self {
        self.filters = input;
        self
    }
    /// <p>Filters for technical cue or shot detection.</p>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::StartSegmentDetectionFilters> {
        &self.filters
    }
    /// Appends an item to `segment_types`.
    ///
    /// To override the contents of this collection use [`set_segment_types`](Self::set_segment_types).
    ///
    /// <p>An array of segment types to detect in the video. Valid values are TECHNICAL_CUE and SHOT.</p>
    pub fn segment_types(mut self, input: crate::types::SegmentType) -> Self {
        let mut v = self.segment_types.unwrap_or_default();
        v.push(input);
        self.segment_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of segment types to detect in the video. Valid values are TECHNICAL_CUE and SHOT.</p>
    pub fn set_segment_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SegmentType>>) -> Self {
        self.segment_types = input;
        self
    }
    /// <p>An array of segment types to detect in the video. Valid values are TECHNICAL_CUE and SHOT.</p>
    pub fn get_segment_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SegmentType>> {
        &self.segment_types
    }
    /// Consumes the builder and constructs a [`StartSegmentDetectionInput`](crate::operation::start_segment_detection::StartSegmentDetectionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_segment_detection::StartSegmentDetectionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_segment_detection::StartSegmentDetectionInput {
            video: self.video,
            client_request_token: self.client_request_token,
            notification_channel: self.notification_channel,
            job_tag: self.job_tag,
            filters: self.filters,
            segment_types: self.segment_types,
        })
    }
}
