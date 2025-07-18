// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListModelCardExportJobsInput {
    /// <p>List export jobs for the model card with the specified name.</p>
    pub model_card_name: ::std::option::Option<::std::string::String>,
    /// <p>List export jobs for the model card with the specified version.</p>
    pub model_card_version: ::std::option::Option<i32>,
    /// <p>Only list model card export jobs that were created after the time specified.</p>
    pub creation_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Only list model card export jobs that were created before the time specified.</p>
    pub creation_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Only list model card export jobs with names that contain the specified string.</p>
    pub model_card_export_job_name_contains: ::std::option::Option<::std::string::String>,
    /// <p>Only list model card export jobs with the specified status.</p>
    pub status_equals: ::std::option::Option<crate::types::ModelCardExportJobStatus>,
    /// <p>Sort model card export jobs by either name or creation time. Sorts by creation time by default.</p>
    pub sort_by: ::std::option::Option<crate::types::ModelCardExportJobSortBy>,
    /// <p>Sort model card export jobs by ascending or descending order.</p>
    pub sort_order: ::std::option::Option<crate::types::ModelCardExportJobSortOrder>,
    /// <p>If the response to a previous <code>ListModelCardExportJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of model card export jobs, use the token in the next request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of model card export jobs to list.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListModelCardExportJobsInput {
    /// <p>List export jobs for the model card with the specified name.</p>
    pub fn model_card_name(&self) -> ::std::option::Option<&str> {
        self.model_card_name.as_deref()
    }
    /// <p>List export jobs for the model card with the specified version.</p>
    pub fn model_card_version(&self) -> ::std::option::Option<i32> {
        self.model_card_version
    }
    /// <p>Only list model card export jobs that were created after the time specified.</p>
    pub fn creation_time_after(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time_after.as_ref()
    }
    /// <p>Only list model card export jobs that were created before the time specified.</p>
    pub fn creation_time_before(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time_before.as_ref()
    }
    /// <p>Only list model card export jobs with names that contain the specified string.</p>
    pub fn model_card_export_job_name_contains(&self) -> ::std::option::Option<&str> {
        self.model_card_export_job_name_contains.as_deref()
    }
    /// <p>Only list model card export jobs with the specified status.</p>
    pub fn status_equals(&self) -> ::std::option::Option<&crate::types::ModelCardExportJobStatus> {
        self.status_equals.as_ref()
    }
    /// <p>Sort model card export jobs by either name or creation time. Sorts by creation time by default.</p>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::ModelCardExportJobSortBy> {
        self.sort_by.as_ref()
    }
    /// <p>Sort model card export jobs by ascending or descending order.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::ModelCardExportJobSortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>If the response to a previous <code>ListModelCardExportJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of model card export jobs, use the token in the next request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of model card export jobs to list.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListModelCardExportJobsInput {
    /// Creates a new builder-style object to manufacture [`ListModelCardExportJobsInput`](crate::operation::list_model_card_export_jobs::ListModelCardExportJobsInput).
    pub fn builder() -> crate::operation::list_model_card_export_jobs::builders::ListModelCardExportJobsInputBuilder {
        crate::operation::list_model_card_export_jobs::builders::ListModelCardExportJobsInputBuilder::default()
    }
}

/// A builder for [`ListModelCardExportJobsInput`](crate::operation::list_model_card_export_jobs::ListModelCardExportJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListModelCardExportJobsInputBuilder {
    pub(crate) model_card_name: ::std::option::Option<::std::string::String>,
    pub(crate) model_card_version: ::std::option::Option<i32>,
    pub(crate) creation_time_after: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) creation_time_before: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) model_card_export_job_name_contains: ::std::option::Option<::std::string::String>,
    pub(crate) status_equals: ::std::option::Option<crate::types::ModelCardExportJobStatus>,
    pub(crate) sort_by: ::std::option::Option<crate::types::ModelCardExportJobSortBy>,
    pub(crate) sort_order: ::std::option::Option<crate::types::ModelCardExportJobSortOrder>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListModelCardExportJobsInputBuilder {
    /// <p>List export jobs for the model card with the specified name.</p>
    /// This field is required.
    pub fn model_card_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_card_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>List export jobs for the model card with the specified name.</p>
    pub fn set_model_card_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_card_name = input;
        self
    }
    /// <p>List export jobs for the model card with the specified name.</p>
    pub fn get_model_card_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_card_name
    }
    /// <p>List export jobs for the model card with the specified version.</p>
    pub fn model_card_version(mut self, input: i32) -> Self {
        self.model_card_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>List export jobs for the model card with the specified version.</p>
    pub fn set_model_card_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.model_card_version = input;
        self
    }
    /// <p>List export jobs for the model card with the specified version.</p>
    pub fn get_model_card_version(&self) -> &::std::option::Option<i32> {
        &self.model_card_version
    }
    /// <p>Only list model card export jobs that were created after the time specified.</p>
    pub fn creation_time_after(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time_after = ::std::option::Option::Some(input);
        self
    }
    /// <p>Only list model card export jobs that were created after the time specified.</p>
    pub fn set_creation_time_after(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time_after = input;
        self
    }
    /// <p>Only list model card export jobs that were created after the time specified.</p>
    pub fn get_creation_time_after(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time_after
    }
    /// <p>Only list model card export jobs that were created before the time specified.</p>
    pub fn creation_time_before(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time_before = ::std::option::Option::Some(input);
        self
    }
    /// <p>Only list model card export jobs that were created before the time specified.</p>
    pub fn set_creation_time_before(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time_before = input;
        self
    }
    /// <p>Only list model card export jobs that were created before the time specified.</p>
    pub fn get_creation_time_before(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time_before
    }
    /// <p>Only list model card export jobs with names that contain the specified string.</p>
    pub fn model_card_export_job_name_contains(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_card_export_job_name_contains = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Only list model card export jobs with names that contain the specified string.</p>
    pub fn set_model_card_export_job_name_contains(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_card_export_job_name_contains = input;
        self
    }
    /// <p>Only list model card export jobs with names that contain the specified string.</p>
    pub fn get_model_card_export_job_name_contains(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_card_export_job_name_contains
    }
    /// <p>Only list model card export jobs with the specified status.</p>
    pub fn status_equals(mut self, input: crate::types::ModelCardExportJobStatus) -> Self {
        self.status_equals = ::std::option::Option::Some(input);
        self
    }
    /// <p>Only list model card export jobs with the specified status.</p>
    pub fn set_status_equals(mut self, input: ::std::option::Option<crate::types::ModelCardExportJobStatus>) -> Self {
        self.status_equals = input;
        self
    }
    /// <p>Only list model card export jobs with the specified status.</p>
    pub fn get_status_equals(&self) -> &::std::option::Option<crate::types::ModelCardExportJobStatus> {
        &self.status_equals
    }
    /// <p>Sort model card export jobs by either name or creation time. Sorts by creation time by default.</p>
    pub fn sort_by(mut self, input: crate::types::ModelCardExportJobSortBy) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sort model card export jobs by either name or creation time. Sorts by creation time by default.</p>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::ModelCardExportJobSortBy>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>Sort model card export jobs by either name or creation time. Sorts by creation time by default.</p>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::ModelCardExportJobSortBy> {
        &self.sort_by
    }
    /// <p>Sort model card export jobs by ascending or descending order.</p>
    pub fn sort_order(mut self, input: crate::types::ModelCardExportJobSortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sort model card export jobs by ascending or descending order.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::ModelCardExportJobSortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>Sort model card export jobs by ascending or descending order.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::ModelCardExportJobSortOrder> {
        &self.sort_order
    }
    /// <p>If the response to a previous <code>ListModelCardExportJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of model card export jobs, use the token in the next request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response to a previous <code>ListModelCardExportJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of model card export jobs, use the token in the next request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response to a previous <code>ListModelCardExportJobs</code> request was truncated, the response includes a <code>NextToken</code>. To retrieve the next set of model card export jobs, use the token in the next request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of model card export jobs to list.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of model card export jobs to list.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of model card export jobs to list.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListModelCardExportJobsInput`](crate::operation::list_model_card_export_jobs::ListModelCardExportJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_model_card_export_jobs::ListModelCardExportJobsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_model_card_export_jobs::ListModelCardExportJobsInput {
            model_card_name: self.model_card_name,
            model_card_version: self.model_card_version,
            creation_time_after: self.creation_time_after,
            creation_time_before: self.creation_time_before,
            model_card_export_job_name_contains: self.model_card_export_job_name_contains,
            status_equals: self.status_equals,
            sort_by: self.sort_by,
            sort_order: self.sort_order,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
