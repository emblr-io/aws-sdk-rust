// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTasksInput {
    /// <p>The farm ID connected to the tasks.</p>
    pub farm_id: ::std::option::Option<::std::string::String>,
    /// <p>The queue ID connected to the tasks.</p>
    pub queue_id: ::std::option::Option<::std::string::String>,
    /// <p>The job ID for the tasks.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The step ID for the tasks.</p>
    pub step_id: ::std::option::Option<::std::string::String>,
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListTasksInput {
    /// <p>The farm ID connected to the tasks.</p>
    pub fn farm_id(&self) -> ::std::option::Option<&str> {
        self.farm_id.as_deref()
    }
    /// <p>The queue ID connected to the tasks.</p>
    pub fn queue_id(&self) -> ::std::option::Option<&str> {
        self.queue_id.as_deref()
    }
    /// <p>The job ID for the tasks.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The step ID for the tasks.</p>
    pub fn step_id(&self) -> ::std::option::Option<&str> {
        self.step_id.as_deref()
    }
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListTasksInput {
    /// Creates a new builder-style object to manufacture [`ListTasksInput`](crate::operation::list_tasks::ListTasksInput).
    pub fn builder() -> crate::operation::list_tasks::builders::ListTasksInputBuilder {
        crate::operation::list_tasks::builders::ListTasksInputBuilder::default()
    }
}

/// A builder for [`ListTasksInput`](crate::operation::list_tasks::ListTasksInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTasksInputBuilder {
    pub(crate) farm_id: ::std::option::Option<::std::string::String>,
    pub(crate) queue_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) step_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListTasksInputBuilder {
    /// <p>The farm ID connected to the tasks.</p>
    /// This field is required.
    pub fn farm_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.farm_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The farm ID connected to the tasks.</p>
    pub fn set_farm_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.farm_id = input;
        self
    }
    /// <p>The farm ID connected to the tasks.</p>
    pub fn get_farm_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.farm_id
    }
    /// <p>The queue ID connected to the tasks.</p>
    /// This field is required.
    pub fn queue_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.queue_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The queue ID connected to the tasks.</p>
    pub fn set_queue_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.queue_id = input;
        self
    }
    /// <p>The queue ID connected to the tasks.</p>
    pub fn get_queue_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.queue_id
    }
    /// <p>The job ID for the tasks.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job ID for the tasks.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The job ID for the tasks.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The step ID for the tasks.</p>
    /// This field is required.
    pub fn step_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.step_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The step ID for the tasks.</p>
    pub fn set_step_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.step_id = input;
        self
    }
    /// <p>The step ID for the tasks.</p>
    pub fn get_step_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.step_id
    }
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results, or <code>null</code> to start from the beginning.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return. Use this parameter with <code>NextToken</code> to get results as a set of sequential pages.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListTasksInput`](crate::operation::list_tasks::ListTasksInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_tasks::ListTasksInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_tasks::ListTasksInput {
            farm_id: self.farm_id,
            queue_id: self.queue_id,
            job_id: self.job_id,
            step_id: self.step_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
