// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon Simple Notification Service topic to which Amazon Rekognition publishes the object detection results and completion status of a video analysis operation.</p>
/// <p>Amazon Rekognition publishes a notification the first time an object of interest or a person is detected in the video stream. For example, if Amazon Rekognition detects a person at second 2, a pet at second 4, and a person again at second 5, Amazon Rekognition sends 2 object class detected notifications, one for a person at second 2 and one for a pet at second 4.</p>
/// <p>Amazon Rekognition also publishes an an end-of-session notification with a summary when the stream processing session is complete.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StreamProcessorNotificationChannel {
    /// <p>The Amazon Resource Number (ARN) of the Amazon Amazon Simple Notification Service topic to which Amazon Rekognition posts the completion status.</p>
    pub sns_topic_arn: ::std::string::String,
}
impl StreamProcessorNotificationChannel {
    /// <p>The Amazon Resource Number (ARN) of the Amazon Amazon Simple Notification Service topic to which Amazon Rekognition posts the completion status.</p>
    pub fn sns_topic_arn(&self) -> &str {
        use std::ops::Deref;
        self.sns_topic_arn.deref()
    }
}
impl StreamProcessorNotificationChannel {
    /// Creates a new builder-style object to manufacture [`StreamProcessorNotificationChannel`](crate::types::StreamProcessorNotificationChannel).
    pub fn builder() -> crate::types::builders::StreamProcessorNotificationChannelBuilder {
        crate::types::builders::StreamProcessorNotificationChannelBuilder::default()
    }
}

/// A builder for [`StreamProcessorNotificationChannel`](crate::types::StreamProcessorNotificationChannel).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StreamProcessorNotificationChannelBuilder {
    pub(crate) sns_topic_arn: ::std::option::Option<::std::string::String>,
}
impl StreamProcessorNotificationChannelBuilder {
    /// <p>The Amazon Resource Number (ARN) of the Amazon Amazon Simple Notification Service topic to which Amazon Rekognition posts the completion status.</p>
    /// This field is required.
    pub fn sns_topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sns_topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the Amazon Amazon Simple Notification Service topic to which Amazon Rekognition posts the completion status.</p>
    pub fn set_sns_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sns_topic_arn = input;
        self
    }
    /// <p>The Amazon Resource Number (ARN) of the Amazon Amazon Simple Notification Service topic to which Amazon Rekognition posts the completion status.</p>
    pub fn get_sns_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.sns_topic_arn
    }
    /// Consumes the builder and constructs a [`StreamProcessorNotificationChannel`](crate::types::StreamProcessorNotificationChannel).
    /// This method will fail if any of the following fields are not set:
    /// - [`sns_topic_arn`](crate::types::builders::StreamProcessorNotificationChannelBuilder::sns_topic_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::StreamProcessorNotificationChannel, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::StreamProcessorNotificationChannel {
            sns_topic_arn: self.sns_topic_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "sns_topic_arn",
                    "sns_topic_arn was not specified but it is required when building StreamProcessorNotificationChannel",
                )
            })?,
        })
    }
}
