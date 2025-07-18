// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeJobsInput {
    /// <p>A set of filters by which to return Jobs.</p>
    pub filters: ::std::option::Option<crate::types::DescribeJobsRequestFilters>,
    /// <p>Maximum number of Jobs to retrieve.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token of the next Job to retrieve.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeJobsInput {
    /// <p>A set of filters by which to return Jobs.</p>
    pub fn filters(&self) -> ::std::option::Option<&crate::types::DescribeJobsRequestFilters> {
        self.filters.as_ref()
    }
    /// <p>Maximum number of Jobs to retrieve.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token of the next Job to retrieve.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeJobsInput {
    /// Creates a new builder-style object to manufacture [`DescribeJobsInput`](crate::operation::describe_jobs::DescribeJobsInput).
    pub fn builder() -> crate::operation::describe_jobs::builders::DescribeJobsInputBuilder {
        crate::operation::describe_jobs::builders::DescribeJobsInputBuilder::default()
    }
}

/// A builder for [`DescribeJobsInput`](crate::operation::describe_jobs::DescribeJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeJobsInputBuilder {
    pub(crate) filters: ::std::option::Option<crate::types::DescribeJobsRequestFilters>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeJobsInputBuilder {
    /// <p>A set of filters by which to return Jobs.</p>
    pub fn filters(mut self, input: crate::types::DescribeJobsRequestFilters) -> Self {
        self.filters = ::std::option::Option::Some(input);
        self
    }
    /// <p>A set of filters by which to return Jobs.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<crate::types::DescribeJobsRequestFilters>) -> Self {
        self.filters = input;
        self
    }
    /// <p>A set of filters by which to return Jobs.</p>
    pub fn get_filters(&self) -> &::std::option::Option<crate::types::DescribeJobsRequestFilters> {
        &self.filters
    }
    /// <p>Maximum number of Jobs to retrieve.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of Jobs to retrieve.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of Jobs to retrieve.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token of the next Job to retrieve.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token of the next Job to retrieve.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token of the next Job to retrieve.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeJobsInput`](crate::operation::describe_jobs::DescribeJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_jobs::DescribeJobsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_jobs::DescribeJobsInput {
            filters: self.filters,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
