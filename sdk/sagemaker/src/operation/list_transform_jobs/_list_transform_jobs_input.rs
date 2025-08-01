// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTransformJobsInput {
    /// <p>A filter that returns only transform jobs created after the specified time.</p>
    pub creation_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A filter that returns only transform jobs created before the specified time.</p>
    pub creation_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A filter that returns only transform jobs modified after the specified time.</p>
    pub last_modified_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A filter that returns only transform jobs modified before the specified time.</p>
    pub last_modified_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A string in the transform job name. This filter returns only transform jobs whose name contains the specified string.</p>
    pub name_contains: ::std::option::Option<::std::string::String>,
    /// <p>A filter that retrieves only transform jobs with a specific status.</p>
    pub status_equals: ::std::option::Option<crate::types::TransformJobStatus>,
    /// <p>The field to sort results by. The default is <code>CreationTime</code>.</p>
    pub sort_by: ::std::option::Option<crate::types::SortBy>,
    /// <p>The sort order for results. The default is <code>Descending</code>.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrder>,
    /// <p>If the result of the previous <code>ListTransformJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of transform jobs, use the token in the next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of transform jobs to return in the response. The default value is <code>10</code>.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListTransformJobsInput {
    /// <p>A filter that returns only transform jobs created after the specified time.</p>
    pub fn creation_time_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time_after.as_ref()
    }
    /// <p>A filter that returns only transform jobs created before the specified time.</p>
    pub fn creation_time_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time_before.as_ref()
    }
    /// <p>A filter that returns only transform jobs modified after the specified time.</p>
    pub fn last_modified_time_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time_after.as_ref()
    }
    /// <p>A filter that returns only transform jobs modified before the specified time.</p>
    pub fn last_modified_time_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_modified_time_before.as_ref()
    }
    /// <p>A string in the transform job name. This filter returns only transform jobs whose name contains the specified string.</p>
    pub fn name_contains(&self) -> ::std::option::Option<&str> {
        self.name_contains.as_deref()
    }
    /// <p>A filter that retrieves only transform jobs with a specific status.</p>
    pub fn status_equals(&self) -> ::std::option::Option<&crate::types::TransformJobStatus> {
        self.status_equals.as_ref()
    }
    /// <p>The field to sort results by. The default is <code>CreationTime</code>.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::SortBy> {
        self.sort_by.as_ref()
    }
    /// <p>The sort order for results. The default is <code>Descending</code>.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>If the result of the previous <code>ListTransformJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of transform jobs, use the token in the next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of transform jobs to return in the response. The default value is <code>10</code>.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListTransformJobsInput {
    /// Creates a new builder-style object to manufacture [`ListTransformJobsInput`](crate::operation::list_transform_jobs::ListTransformJobsInput).
    pub fn builder() -> crate::operation::list_transform_jobs::builders::ListTransformJobsInputBuilder {
        crate::operation::list_transform_jobs::builders::ListTransformJobsInputBuilder::default()
    }
}

/// A builder for [`ListTransformJobsInput`](crate::operation::list_transform_jobs::ListTransformJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTransformJobsInputBuilder {
    pub(crate) creation_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) creation_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) name_contains: ::std::option::Option<::std::string::String>,
    pub(crate) status_equals: ::std::option::Option<crate::types::TransformJobStatus>,
    pub(crate) sort_by: ::std::option::Option<crate::types::SortBy>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrder>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListTransformJobsInputBuilder {
    /// <p>A filter that returns only transform jobs created after the specified time.</p>
    pub fn creation_time_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only transform jobs created after the specified time.</p>
    pub fn set_creation_time_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time_after = input;
        self
    }
    /// <p>A filter that returns only transform jobs created after the specified time.</p>
    pub fn get_creation_time_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time_after
    }
    /// <p>A filter that returns only transform jobs created before the specified time.</p>
    pub fn creation_time_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only transform jobs created before the specified time.</p>
    pub fn set_creation_time_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time_before = input;
        self
    }
    /// <p>A filter that returns only transform jobs created before the specified time.</p>
    pub fn get_creation_time_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time_before
    }
    /// <p>A filter that returns only transform jobs modified after the specified time.</p>
    pub fn last_modified_time_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only transform jobs modified after the specified time.</p>
    pub fn set_last_modified_time_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time_after = input;
        self
    }
    /// <p>A filter that returns only transform jobs modified after the specified time.</p>
    pub fn get_last_modified_time_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time_after
    }
    /// <p>A filter that returns only transform jobs modified before the specified time.</p>
    pub fn last_modified_time_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that returns only transform jobs modified before the specified time.</p>
    pub fn set_last_modified_time_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time_before = input;
        self
    }
    /// <p>A filter that returns only transform jobs modified before the specified time.</p>
    pub fn get_last_modified_time_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time_before
    }
    /// <p>A string in the transform job name. This filter returns only transform jobs whose name contains the specified string.</p>
    pub fn name_contains(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name_contains = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string in the transform job name. This filter returns only transform jobs whose name contains the specified string.</p>
    pub fn set_name_contains(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name_contains = input;
        self
    }
    /// <p>A string in the transform job name. This filter returns only transform jobs whose name contains the specified string.</p>
    pub fn get_name_contains(&self) -> &::std::option::Option<::std::string::String> {
        &self.name_contains
    }
    /// <p>A filter that retrieves only transform jobs with a specific status.</p>
    pub fn status_equals(mut self, input: crate::types::TransformJobStatus) -> Self {
        self.status_equals = ::std::option::Option::Some(input);
        self
    }
    /// <p>A filter that retrieves only transform jobs with a specific status.</p>
    pub fn set_status_equals(mut self, input: ::std::option::Option<crate::types::TransformJobStatus>) -> Self {
        self.status_equals = input;
        self
    }
    /// <p>A filter that retrieves only transform jobs with a specific status.</p>
    pub fn get_status_equals(&self) -> &::std::option::Option<crate::types::TransformJobStatus> {
        &self.status_equals
    }
    /// <p>The field to sort results by. The default is <code>CreationTime</code>.</p>
    pub fn sort_by(mut self, input: crate::types::SortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>The field to sort results by. The default is <code>CreationTime</code>.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::SortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>The field to sort results by. The default is <code>CreationTime</code>.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::SortBy> {
        &self.sort_by
    }
    /// <p>The sort order for results. The default is <code>Descending</code>.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sort order for results. The default is <code>Descending</code>.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The sort order for results. The default is <code>Descending</code>.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrder> {
        &self.sort_order
    }
    /// <p>If the result of the previous <code>ListTransformJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of transform jobs, use the token in the next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the result of the previous <code>ListTransformJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of transform jobs, use the token in the next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the result of the previous <code>ListTransformJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of transform jobs, use the token in the next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of transform jobs to return in the response. The default value is <code>10</code>.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of transform jobs to return in the response. The default value is <code>10</code>.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of transform jobs to return in the response. The default value is <code>10</code>.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListTransformJobsInput`](crate::operation::list_transform_jobs::ListTransformJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_transform_jobs::ListTransformJobsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_transform_jobs::ListTransformJobsInput {
            creation_time_after: self.creation_time_after,
            creation_time_before: self.creation_time_before,
            last_modified_time_after: self.last_modified_time_after,
            last_modified_time_before: self.last_modified_time_before,
            name_contains: self.name_contains,
            status_equals: self.status_equals,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
