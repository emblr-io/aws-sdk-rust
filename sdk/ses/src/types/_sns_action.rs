// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>When included in a receipt rule, this action publishes a notification to Amazon Simple Notification Service (Amazon SNS). This action includes a complete copy of the email content in the Amazon SNS notifications. Amazon SNS notifications for all other actions simply provide information about the email. They do not include the email content itself.</p>
/// <p>If you own the Amazon SNS topic, you don't need to do anything to give Amazon SES permission to publish emails to it. However, if you don't own the Amazon SNS topic, you need to attach a policy to the topic to give Amazon SES permissions to access it. For information about giving permissions, see the <a href="https://docs.aws.amazon.com/ses/latest/dg/receiving-email-permissions.html">Amazon SES Developer Guide</a>.</p><important>
/// <p>You can only publish emails that are 150 KB or less (including the header) to Amazon SNS. Larger emails bounce. If you anticipate emails larger than 150 KB, use the S3 action instead.</p>
/// </important>
/// <p>For information about using a receipt rule to publish an Amazon SNS notification, see the <a href="https://docs.aws.amazon.com/ses/latest/dg/receiving-email-action-sns.html">Amazon SES Developer Guide</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnsAction {
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to notify. You can find the ARN of a topic by using the <a href="https://docs.aws.amazon.com/sns/latest/api/API_ListTopics.html">ListTopics</a> operation in Amazon SNS.</p>
    /// <p>For more information about Amazon SNS topics, see the <a href="https://docs.aws.amazon.com/sns/latest/dg/CreateTopic.html">Amazon SNS Developer Guide</a>.</p>
    pub topic_arn: ::std::string::String,
    /// <p>The encoding to use for the email within the Amazon SNS notification. UTF-8 is easier to use, but may not preserve all special characters when a message was encoded with a different encoding format. Base64 preserves all special characters. The default value is UTF-8.</p>
    pub encoding: ::std::option::Option<crate::types::SnsActionEncoding>,
}
impl SnsAction {
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to notify. You can find the ARN of a topic by using the <a href="https://docs.aws.amazon.com/sns/latest/api/API_ListTopics.html">ListTopics</a> operation in Amazon SNS.</p>
    /// <p>For more information about Amazon SNS topics, see the <a href="https://docs.aws.amazon.com/sns/latest/dg/CreateTopic.html">Amazon SNS Developer Guide</a>.</p>
    pub fn topic_arn(&self) -> &str {
        use std::ops::Deref;
        self.topic_arn.deref()
    }
    /// <p>The encoding to use for the email within the Amazon SNS notification. UTF-8 is easier to use, but may not preserve all special characters when a message was encoded with a different encoding format. Base64 preserves all special characters. The default value is UTF-8.</p>
    pub fn encoding(&self) -> ::std::option::Option<&crate::types::SnsActionEncoding> {
        self.encoding.as_ref()
    }
}
impl SnsAction {
    /// Creates a new builder-style object to manufacture [`SnsAction`](crate::types::SnsAction).
    pub fn builder() -> crate::types::builders::SnsActionBuilder {
        crate::types::builders::SnsActionBuilder::default()
    }
}

/// A builder for [`SnsAction`](crate::types::SnsAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnsActionBuilder {
    pub(crate) topic_arn: ::std::option::Option<::std::string::String>,
    pub(crate) encoding: ::std::option::Option<crate::types::SnsActionEncoding>,
}
impl SnsActionBuilder {
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to notify. You can find the ARN of a topic by using the <a href="https://docs.aws.amazon.com/sns/latest/api/API_ListTopics.html">ListTopics</a> operation in Amazon SNS.</p>
    /// <p>For more information about Amazon SNS topics, see the <a href="https://docs.aws.amazon.com/sns/latest/dg/CreateTopic.html">Amazon SNS Developer Guide</a>.</p>
    /// This field is required.
    pub fn topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to notify. You can find the ARN of a topic by using the <a href="https://docs.aws.amazon.com/sns/latest/api/API_ListTopics.html">ListTopics</a> operation in Amazon SNS.</p>
    /// <p>For more information about Amazon SNS topics, see the <a href="https://docs.aws.amazon.com/sns/latest/dg/CreateTopic.html">Amazon SNS Developer Guide</a>.</p>
    pub fn set_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Amazon SNS topic to notify. You can find the ARN of a topic by using the <a href="https://docs.aws.amazon.com/sns/latest/api/API_ListTopics.html">ListTopics</a> operation in Amazon SNS.</p>
    /// <p>For more information about Amazon SNS topics, see the <a href="https://docs.aws.amazon.com/sns/latest/dg/CreateTopic.html">Amazon SNS Developer Guide</a>.</p>
    pub fn get_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_arn
    }
    /// <p>The encoding to use for the email within the Amazon SNS notification. UTF-8 is easier to use, but may not preserve all special characters when a message was encoded with a different encoding format. Base64 preserves all special characters. The default value is UTF-8.</p>
    pub fn encoding(mut self, input: crate::types::SnsActionEncoding) -> Self {
        self.encoding = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encoding to use for the email within the Amazon SNS notification. UTF-8 is easier to use, but may not preserve all special characters when a message was encoded with a different encoding format. Base64 preserves all special characters. The default value is UTF-8.</p>
    pub fn set_encoding(mut self, input: ::std::option::Option<crate::types::SnsActionEncoding>) -> Self {
        self.encoding = input;
        self
    }
    /// <p>The encoding to use for the email within the Amazon SNS notification. UTF-8 is easier to use, but may not preserve all special characters when a message was encoded with a different encoding format. Base64 preserves all special characters. The default value is UTF-8.</p>
    pub fn get_encoding(&self) -> &::std::option::Option<crate::types::SnsActionEncoding> {
        &self.encoding
    }
    /// Consumes the builder and constructs a [`SnsAction`](crate::types::SnsAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`topic_arn`](crate::types::builders::SnsActionBuilder::topic_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::SnsAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SnsAction {
            topic_arn: self.topic_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "topic_arn",
                    "topic_arn was not specified but it is required when building SnsAction",
                )
            })?,
            encoding: self.encoding,
        })
    }
}
