// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an action to publish data to an Amazon SQS queue.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SqsAction {
    /// <p>The ARN of the IAM role that grants access.</p>
    pub role_arn: ::std::string::String,
    /// <p>The URL of the Amazon SQS queue.</p>
    pub queue_url: ::std::string::String,
    /// <p>Specifies whether to use Base64 encoding.</p>
    pub use_base64: ::std::option::Option<bool>,
}
impl SqsAction {
    /// <p>The ARN of the IAM role that grants access.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
    /// <p>The URL of the Amazon SQS queue.</p>
    pub fn queue_url(&self) -> &str {
        use std::ops::Deref;
        self.queue_url.deref()
    }
    /// <p>Specifies whether to use Base64 encoding.</p>
    pub fn use_base64(&self) -> ::std::option::Option<bool> {
        self.use_base64
    }
}
impl SqsAction {
    /// Creates a new builder-style object to manufacture [`SqsAction`](crate::types::SqsAction).
    pub fn builder() -> crate::types::builders::SqsActionBuilder {
        crate::types::builders::SqsActionBuilder::default()
    }
}

/// A builder for [`SqsAction`](crate::types::SqsAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SqsActionBuilder {
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) queue_url: ::std::option::Option<::std::string::String>,
    pub(crate) use_base64: ::std::option::Option<bool>,
}
impl SqsActionBuilder {
    /// <p>The ARN of the IAM role that grants access.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM role that grants access.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The ARN of the IAM role that grants access.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The URL of the Amazon SQS queue.</p>
    /// This field is required.
    pub fn queue_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the Amazon SQS queue.</p>
    pub fn set_queue_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_url = input;
        self
    }
    /// <p>The URL of the Amazon SQS queue.</p>
    pub fn get_queue_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_url
    }
    /// <p>Specifies whether to use Base64 encoding.</p>
    pub fn use_base64(mut self, input: bool) -> Self {
        self.use_base64 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to use Base64 encoding.</p>
    pub fn set_use_base64(mut self, input: ::std::option::Option<bool>) -> Self {
        self.use_base64 = input;
        self
    }
    /// <p>Specifies whether to use Base64 encoding.</p>
    pub fn get_use_base64(&self) -> &::std::option::Option<bool> {
        &self.use_base64
    }
    /// Consumes the builder and constructs a [`SqsAction`](crate::types::SqsAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`role_arn`](crate::types::builders::SqsActionBuilder::role_arn)
    /// - [`queue_url`](crate::types::builders::SqsActionBuilder::queue_url)
    pub fn build(self) -> ::std::result::Result<crate::types::SqsAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SqsAction {
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building SqsAction",
                )
            })?,
            queue_url: self.queue_url.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "queue_url",
                    "queue_url was not specified but it is required when building SqsAction",
                )
            })?,
            use_base64: self.use_base64,
        })
    }
}
