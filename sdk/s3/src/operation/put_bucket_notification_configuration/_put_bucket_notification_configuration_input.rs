// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBucketNotificationConfigurationInput {
    /// <p>The name of the bucket.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>A container for specifying the notification configuration of the bucket. If this element is empty, notifications are turned off for the bucket.</p>
    pub notification_configuration: ::std::option::Option<crate::types::NotificationConfiguration>,
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub expected_bucket_owner: ::std::option::Option<::std::string::String>,
    /// <p>Skips validation of Amazon SQS, Amazon SNS, and Lambda destinations. True or false value.</p>
    pub skip_destination_validation: ::std::option::Option<bool>,
}
impl PutBucketNotificationConfigurationInput {
    /// <p>The name of the bucket.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>A container for specifying the notification configuration of the bucket. If this element is empty, notifications are turned off for the bucket.</p>
    pub fn notification_configuration(&self) -> ::std::option::Option<&crate::types::NotificationConfiguration> {
        self.notification_configuration.as_ref()
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.expected_bucket_owner.as_deref()
    }
    /// <p>Skips validation of Amazon SQS, Amazon SNS, and Lambda destinations. True or false value.</p>
    pub fn skip_destination_validation(&self) -> ::std::option::Option<bool> {
        self.skip_destination_validation
    }
}
impl PutBucketNotificationConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutBucketNotificationConfigurationInput`](crate::operation::put_bucket_notification_configuration::PutBucketNotificationConfigurationInput).
    pub fn builder() -> crate::operation::put_bucket_notification_configuration::builders::PutBucketNotificationConfigurationInputBuilder {
        crate::operation::put_bucket_notification_configuration::builders::PutBucketNotificationConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutBucketNotificationConfigurationInput`](crate::operation::put_bucket_notification_configuration::PutBucketNotificationConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutBucketNotificationConfigurationInputBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) notification_configuration: ::std::option::Option<crate::types::NotificationConfiguration>,
    pub(crate) expected_bucket_owner: ::std::option::Option<::std::string::String>,
    pub(crate) skip_destination_validation: ::std::option::Option<bool>,
}
impl PutBucketNotificationConfigurationInputBuilder {
    /// <p>The name of the bucket.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bucket.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of the bucket.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>A container for specifying the notification configuration of the bucket. If this element is empty, notifications are turned off for the bucket.</p>
    /// This field is required.
    pub fn notification_configuration(mut self, input: crate::types::NotificationConfiguration) -> Self {
        self.notification_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>A container for specifying the notification configuration of the bucket. If this element is empty, notifications are turned off for the bucket.</p>
    pub fn set_notification_configuration(mut self, input: ::std::option::Option<crate::types::NotificationConfiguration>) -> Self {
        self.notification_configuration = input;
        self
    }
    /// <p>A container for specifying the notification configuration of the bucket. If this element is empty, notifications are turned off for the bucket.</p>
    pub fn get_notification_configuration(&self) -> &::std::option::Option<crate::types::NotificationConfiguration> {
        &self.notification_configuration
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn set_expected_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_bucket_owner = input;
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn get_expected_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_bucket_owner
    }
    /// <p>Skips validation of Amazon SQS, Amazon SNS, and Lambda destinations. True or false value.</p>
    pub fn skip_destination_validation(mut self, input: bool) -> Self {
        self.skip_destination_validation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Skips validation of Amazon SQS, Amazon SNS, and Lambda destinations. True or false value.</p>
    pub fn set_skip_destination_validation(mut self, input: ::std::option::Option<bool>) -> Self {
        self.skip_destination_validation = input;
        self
    }
    /// <p>Skips validation of Amazon SQS, Amazon SNS, and Lambda destinations. True or false value.</p>
    pub fn get_skip_destination_validation(&self) -> &::std::option::Option<bool> {
        &self.skip_destination_validation
    }
    /// Consumes the builder and constructs a [`PutBucketNotificationConfigurationInput`](crate::operation::put_bucket_notification_configuration::PutBucketNotificationConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_bucket_notification_configuration::PutBucketNotificationConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_bucket_notification_configuration::PutBucketNotificationConfigurationInput {
                bucket: self.bucket,
                notification_configuration: self.notification_configuration,
                expected_bucket_owner: self.expected_bucket_owner,
                skip_destination_validation: self.skip_destination_validation,
            },
        )
    }
}
