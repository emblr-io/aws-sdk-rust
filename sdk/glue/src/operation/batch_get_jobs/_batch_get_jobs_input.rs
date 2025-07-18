// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchGetJobsInput {
    /// <p>A list of job names, which might be the names returned from the <code>ListJobs</code> operation.</p>
    pub job_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetJobsInput {
    /// <p>A list of job names, which might be the names returned from the <code>ListJobs</code> operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.job_names.is_none()`.
    pub fn job_names(&self) -> &[::std::string::String] {
        self.job_names.as_deref().unwrap_or_default()
    }
}
impl BatchGetJobsInput {
    /// Creates a new builder-style object to manufacture [`BatchGetJobsInput`](crate::operation::batch_get_jobs::BatchGetJobsInput).
    pub fn builder() -> crate::operation::batch_get_jobs::builders::BatchGetJobsInputBuilder {
        crate::operation::batch_get_jobs::builders::BatchGetJobsInputBuilder::default()
    }
}

/// A builder for [`BatchGetJobsInput`](crate::operation::batch_get_jobs::BatchGetJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchGetJobsInputBuilder {
    pub(crate) job_names: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl BatchGetJobsInputBuilder {
    /// Appends an item to `job_names`.
    ///
    /// To override the contents of this collection use [`set_job_names`](Self::set_job_names).
    ///
    /// <p>A list of job names, which might be the names returned from the <code>ListJobs</code> operation.</p>
    pub fn job_names(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.job_names.unwrap_or_default();
        v.push(input.into());
        self.job_names = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of job names, which might be the names returned from the <code>ListJobs</code> operation.</p>
    pub fn set_job_names(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.job_names = input;
        self
    }
    /// <p>A list of job names, which might be the names returned from the <code>ListJobs</code> operation.</p>
    pub fn get_job_names(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.job_names
    }
    /// Consumes the builder and constructs a [`BatchGetJobsInput`](crate::operation::batch_get_jobs::BatchGetJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_get_jobs::BatchGetJobsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::batch_get_jobs::BatchGetJobsInput { job_names: self.job_names })
    }
}
