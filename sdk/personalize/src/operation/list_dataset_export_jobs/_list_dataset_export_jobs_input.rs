// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDatasetExportJobsInput {
    /// <p>The Amazon Resource Name (ARN) of the dataset to list the dataset export jobs for.</p>
    pub dataset_arn: ::std::option::Option<::std::string::String>,
    /// <p>A token returned from the previous call to <code>ListDatasetExportJobs</code> for getting the next set of dataset export jobs (if they exist).</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of dataset export jobs to return.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListDatasetExportJobsInput {
    /// <p>The Amazon Resource Name (ARN) of the dataset to list the dataset export jobs for.</p>
    pub fn dataset_arn(&self) -> ::std::option::Option<&str> {
        self.dataset_arn.as_deref()
    }
    /// <p>A token returned from the previous call to <code>ListDatasetExportJobs</code> for getting the next set of dataset export jobs (if they exist).</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of dataset export jobs to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListDatasetExportJobsInput {
    /// Creates a new builder-style object to manufacture [`ListDatasetExportJobsInput`](crate::operation::list_dataset_export_jobs::ListDatasetExportJobsInput).
    pub fn builder() -> crate::operation::list_dataset_export_jobs::builders::ListDatasetExportJobsInputBuilder {
        crate::operation::list_dataset_export_jobs::builders::ListDatasetExportJobsInputBuilder::default()
    }
}

/// A builder for [`ListDatasetExportJobsInput`](crate::operation::list_dataset_export_jobs::ListDatasetExportJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDatasetExportJobsInputBuilder {
    pub(crate) dataset_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListDatasetExportJobsInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the dataset to list the dataset export jobs for.</p>
    pub fn dataset_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dataset_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset to list the dataset export jobs for.</p>
    pub fn set_dataset_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dataset_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the dataset to list the dataset export jobs for.</p>
    pub fn get_dataset_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.dataset_arn
    }
    /// <p>A token returned from the previous call to <code>ListDatasetExportJobs</code> for getting the next set of dataset export jobs (if they exist).</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token returned from the previous call to <code>ListDatasetExportJobs</code> for getting the next set of dataset export jobs (if they exist).</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token returned from the previous call to <code>ListDatasetExportJobs</code> for getting the next set of dataset export jobs (if they exist).</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of dataset export jobs to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of dataset export jobs to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of dataset export jobs to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListDatasetExportJobsInput`](crate::operation::list_dataset_export_jobs::ListDatasetExportJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_dataset_export_jobs::ListDatasetExportJobsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_dataset_export_jobs::ListDatasetExportJobsInput {
            dataset_arn: self.dataset_arn,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
