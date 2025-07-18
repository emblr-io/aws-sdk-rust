// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeJobLogItemsInput {
    /// <p>The ID of the Job for which Job log items will be retrieved.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of Job log items to retrieve.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token of the next Job log items to retrieve.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeJobLogItemsInput {
    /// <p>The ID of the Job for which Job log items will be retrieved.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>Maximum number of Job log items to retrieve.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token of the next Job log items to retrieve.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeJobLogItemsInput {
    /// Creates a new builder-style object to manufacture [`DescribeJobLogItemsInput`](crate::operation::describe_job_log_items::DescribeJobLogItemsInput).
    pub fn builder() -> crate::operation::describe_job_log_items::builders::DescribeJobLogItemsInputBuilder {
        crate::operation::describe_job_log_items::builders::DescribeJobLogItemsInputBuilder::default()
    }
}

/// A builder for [`DescribeJobLogItemsInput`](crate::operation::describe_job_log_items::DescribeJobLogItemsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeJobLogItemsInputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeJobLogItemsInputBuilder {
    /// <p>The ID of the Job for which Job log items will be retrieved.</p>
    /// This field is required.
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Job for which Job log items will be retrieved.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The ID of the Job for which Job log items will be retrieved.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>Maximum number of Job log items to retrieve.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of Job log items to retrieve.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of Job log items to retrieve.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token of the next Job log items to retrieve.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token of the next Job log items to retrieve.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token of the next Job log items to retrieve.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeJobLogItemsInput`](crate::operation::describe_job_log_items::DescribeJobLogItemsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_job_log_items::DescribeJobLogItemsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_job_log_items::DescribeJobLogItemsInput {
            job_id: self.job_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
