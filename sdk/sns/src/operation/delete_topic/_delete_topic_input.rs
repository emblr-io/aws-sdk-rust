// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTopicInput {
    /// <p>The ARN of the topic you want to delete.</p>
    pub topic_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteTopicInput {
    /// <p>The ARN of the topic you want to delete.</p>
    pub fn topic_arn(&self) -> ::std::option::Option<&str> {
        self.topic_arn.as_deref()
    }
}
impl DeleteTopicInput {
    /// Creates a new builder-style object to manufacture [`DeleteTopicInput`](crate::operation::delete_topic::DeleteTopicInput).
    pub fn builder() -> crate::operation::delete_topic::builders::DeleteTopicInputBuilder {
        crate::operation::delete_topic::builders::DeleteTopicInputBuilder::default()
    }
}

/// A builder for [`DeleteTopicInput`](crate::operation::delete_topic::DeleteTopicInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTopicInputBuilder {
    pub(crate) topic_arn: ::std::option::Option<::std::string::String>,
}
impl DeleteTopicInputBuilder {
    /// <p>The ARN of the topic you want to delete.</p>
    /// This field is required.
    pub fn topic_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.topic_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the topic you want to delete.</p>
    pub fn set_topic_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.topic_arn = input;
        self
    }
    /// <p>The ARN of the topic you want to delete.</p>
    pub fn get_topic_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.topic_arn
    }
    /// Consumes the builder and constructs a [`DeleteTopicInput`](crate::operation::delete_topic::DeleteTopicInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_topic::DeleteTopicInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_topic::DeleteTopicInput { topic_arn: self.topic_arn })
    }
}
