// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the task assigned to one or many devices.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaskSummary {
    /// <p>The task ID.</p>
    pub task_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub task_arn: ::std::option::Option<::std::string::String>,
    /// <p>The state of the task assigned to one or many devices.</p>
    pub state: ::std::option::Option<crate::types::TaskState>,
    /// <p>Optional metadata that you assign to a resource. You can use tags to categorize a resource in different ways, such as by purpose, owner, or environment.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl TaskSummary {
    /// <p>The task ID.</p>
    pub fn task_id(&self) -> &str {
        use std::ops::Deref;
        self.task_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub fn task_arn(&self) -> ::std::option::Option<&str> {
        self.task_arn.as_deref()
    }
    /// <p>The state of the task assigned to one or many devices.</p>
    pub fn state(&self) -> ::std::option::Option<&crate::types::TaskState> {
        self.state.as_ref()
    }
    /// <p>Optional metadata that you assign to a resource. You can use tags to categorize a resource in different ways, such as by purpose, owner, or environment.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl TaskSummary {
    /// Creates a new builder-style object to manufacture [`TaskSummary`](crate::types::TaskSummary).
    pub fn builder() -> crate::types::builders::TaskSummaryBuilder {
        crate::types::builders::TaskSummaryBuilder::default()
    }
}

/// A builder for [`TaskSummary`](crate::types::TaskSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaskSummaryBuilder {
    pub(crate) task_id: ::std::option::Option<::std::string::String>,
    pub(crate) task_arn: ::std::option::Option<::std::string::String>,
    pub(crate) state: ::std::option::Option<crate::types::TaskState>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl TaskSummaryBuilder {
    /// <p>The task ID.</p>
    /// This field is required.
    pub fn task_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The task ID.</p>
    pub fn set_task_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_id = input;
        self
    }
    /// <p>The task ID.</p>
    pub fn get_task_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_id
    }
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub fn task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub fn set_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the task.</p>
    pub fn get_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_arn
    }
    /// <p>The state of the task assigned to one or many devices.</p>
    pub fn state(mut self, input: crate::types::TaskState) -> Self {
        self.state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of the task assigned to one or many devices.</p>
    pub fn set_state(mut self, input: ::std::option::Option<crate::types::TaskState>) -> Self {
        self.state = input;
        self
    }
    /// <p>The state of the task assigned to one or many devices.</p>
    pub fn get_state(&self) -> &::std::option::Option<crate::types::TaskState> {
        &self.state
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Optional metadata that you assign to a resource. You can use tags to categorize a resource in different ways, such as by purpose, owner, or environment.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Optional metadata that you assign to a resource. You can use tags to categorize a resource in different ways, such as by purpose, owner, or environment.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Optional metadata that you assign to a resource. You can use tags to categorize a resource in different ways, such as by purpose, owner, or environment.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`TaskSummary`](crate::types::TaskSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`task_id`](crate::types::builders::TaskSummaryBuilder::task_id)
    pub fn build(self) -> ::std::result::Result<crate::types::TaskSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TaskSummary {
            task_id: self.task_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "task_id",
                    "task_id was not specified but it is required when building TaskSummary",
                )
            })?,
            task_arn: self.task_arn,
            state: self.state,
            tags: self.tags,
        })
    }
}
