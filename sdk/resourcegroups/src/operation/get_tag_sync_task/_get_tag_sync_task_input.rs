// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTagSyncTaskInput {
    /// <p>The Amazon resource name (ARN) of the tag-sync task.</p>
    pub task_arn: ::std::option::Option<::std::string::String>,
}
impl GetTagSyncTaskInput {
    /// <p>The Amazon resource name (ARN) of the tag-sync task.</p>
    pub fn task_arn(&self) -> ::std::option::Option<&str> {
        self.task_arn.as_deref()
    }
}
impl GetTagSyncTaskInput {
    /// Creates a new builder-style object to manufacture [`GetTagSyncTaskInput`](crate::operation::get_tag_sync_task::GetTagSyncTaskInput).
    pub fn builder() -> crate::operation::get_tag_sync_task::builders::GetTagSyncTaskInputBuilder {
        crate::operation::get_tag_sync_task::builders::GetTagSyncTaskInputBuilder::default()
    }
}

/// A builder for [`GetTagSyncTaskInput`](crate::operation::get_tag_sync_task::GetTagSyncTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTagSyncTaskInputBuilder {
    pub(crate) task_arn: ::std::option::Option<::std::string::String>,
}
impl GetTagSyncTaskInputBuilder {
    /// <p>The Amazon resource name (ARN) of the tag-sync task.</p>
    /// This field is required.
    pub fn task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon resource name (ARN) of the tag-sync task.</p>
    pub fn set_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_arn = input;
        self
    }
    /// <p>The Amazon resource name (ARN) of the tag-sync task.</p>
    pub fn get_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_arn
    }
    /// Consumes the builder and constructs a [`GetTagSyncTaskInput`](crate::operation::get_tag_sync_task::GetTagSyncTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_tag_sync_task::GetTagSyncTaskInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_tag_sync_task::GetTagSyncTaskInput { task_arn: self.task_arn })
    }
}
