// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for using a Amazon SQS stream as a target.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct PipeTargetSqsQueueParameters {
    /// <p>The FIFO message group ID to use as the target.</p>
    pub message_group_id: ::std::option::Option<::std::string::String>,
    /// <p>This parameter applies only to FIFO (first-in-first-out) queues.</p>
    /// <p>The token used for deduplication of sent messages.</p>
    pub message_deduplication_id: ::std::option::Option<::std::string::String>,
}
impl PipeTargetSqsQueueParameters {
    /// <p>The FIFO message group ID to use as the target.</p>
    pub fn message_group_id(&self) -> ::std::option::Option<&str> {
        self.message_group_id.as_deref()
    }
    /// <p>This parameter applies only to FIFO (first-in-first-out) queues.</p>
    /// <p>The token used for deduplication of sent messages.</p>
    pub fn message_deduplication_id(&self) -> ::std::option::Option<&str> {
        self.message_deduplication_id.as_deref()
    }
}
impl ::std::fmt::Debug for PipeTargetSqsQueueParameters {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("PipeTargetSqsQueueParameters");
        formatter.field("message_group_id", &"*** Sensitive Data Redacted ***");
        formatter.field("message_deduplication_id", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl PipeTargetSqsQueueParameters {
    /// Creates a new builder-style object to manufacture [`PipeTargetSqsQueueParameters`](crate::types::PipeTargetSqsQueueParameters).
    pub fn builder() -> crate::types::builders::PipeTargetSqsQueueParametersBuilder {
        crate::types::builders::PipeTargetSqsQueueParametersBuilder::default()
    }
}

/// A builder for [`PipeTargetSqsQueueParameters`](crate::types::PipeTargetSqsQueueParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct PipeTargetSqsQueueParametersBuilder {
    pub(crate) message_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) message_deduplication_id: ::std::option::Option<::std::string::String>,
}
impl PipeTargetSqsQueueParametersBuilder {
    /// <p>The FIFO message group ID to use as the target.</p>
    pub fn message_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The FIFO message group ID to use as the target.</p>
    pub fn set_message_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_group_id = input;
        self
    }
    /// <p>The FIFO message group ID to use as the target.</p>
    pub fn get_message_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.message_group_id
    }
    /// <p>This parameter applies only to FIFO (first-in-first-out) queues.</p>
    /// <p>The token used for deduplication of sent messages.</p>
    pub fn message_deduplication_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message_deduplication_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This parameter applies only to FIFO (first-in-first-out) queues.</p>
    /// <p>The token used for deduplication of sent messages.</p>
    pub fn set_message_deduplication_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message_deduplication_id = input;
        self
    }
    /// <p>This parameter applies only to FIFO (first-in-first-out) queues.</p>
    /// <p>The token used for deduplication of sent messages.</p>
    pub fn get_message_deduplication_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.message_deduplication_id
    }
    /// Consumes the builder and constructs a [`PipeTargetSqsQueueParameters`](crate::types::PipeTargetSqsQueueParameters).
    pub fn build(self) -> crate::types::PipeTargetSqsQueueParameters {
        crate::types::PipeTargetSqsQueueParameters {
            message_group_id: self.message_group_id,
            message_deduplication_id: self.message_deduplication_id,
        }
    }
}
impl ::std::fmt::Debug for PipeTargetSqsQueueParametersBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("PipeTargetSqsQueueParametersBuilder");
        formatter.field("message_group_id", &"*** Sensitive Data Redacted ***");
        formatter.field("message_deduplication_id", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
