// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMedicalScribeJobsInput {
    /// <p>Returns only Medical Scribe jobs with the specified status. Jobs are ordered by creation date, with the newest job first. If you do not include <code>Status</code>, all Medical Scribe jobs are returned.</p>
    pub status: ::std::option::Option<crate::types::MedicalScribeJobStatus>,
    /// <p>Returns only the Medical Scribe jobs that contain the specified string. The search is not case sensitive.</p>
    pub job_name_contains: ::std::option::Option<::std::string::String>,
    /// <p>If your <code>ListMedicalScribeJobs</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of Medical Scribe jobs to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListMedicalScribeJobsInput {
    /// <p>Returns only Medical Scribe jobs with the specified status. Jobs are ordered by creation date, with the newest job first. If you do not include <code>Status</code>, all Medical Scribe jobs are returned.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::MedicalScribeJobStatus> {
        self.status.as_ref()
    }
    /// <p>Returns only the Medical Scribe jobs that contain the specified string. The search is not case sensitive.</p>
    pub fn job_name_contains(&self) -> ::std::option::Option<&str> {
        self.job_name_contains.as_deref()
    }
    /// <p>If your <code>ListMedicalScribeJobs</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of Medical Scribe jobs to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListMedicalScribeJobsInput {
    /// Creates a new builder-style object to manufacture [`ListMedicalScribeJobsInput`](crate::operation::list_medical_scribe_jobs::ListMedicalScribeJobsInput).
    pub fn builder() -> crate::operation::list_medical_scribe_jobs::builders::ListMedicalScribeJobsInputBuilder {
        crate::operation::list_medical_scribe_jobs::builders::ListMedicalScribeJobsInputBuilder::default()
    }
}

/// A builder for [`ListMedicalScribeJobsInput`](crate::operation::list_medical_scribe_jobs::ListMedicalScribeJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMedicalScribeJobsInputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::MedicalScribeJobStatus>,
    pub(crate) job_name_contains: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListMedicalScribeJobsInputBuilder {
    /// <p>Returns only Medical Scribe jobs with the specified status. Jobs are ordered by creation date, with the newest job first. If you do not include <code>Status</code>, all Medical Scribe jobs are returned.</p>
    pub fn status(mut self, input: crate::types::MedicalScribeJobStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns only Medical Scribe jobs with the specified status. Jobs are ordered by creation date, with the newest job first. If you do not include <code>Status</code>, all Medical Scribe jobs are returned.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::MedicalScribeJobStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Returns only Medical Scribe jobs with the specified status. Jobs are ordered by creation date, with the newest job first. If you do not include <code>Status</code>, all Medical Scribe jobs are returned.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::MedicalScribeJobStatus> {
        &self.status
    }
    /// <p>Returns only the Medical Scribe jobs that contain the specified string. The search is not case sensitive.</p>
    pub fn job_name_contains(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_name_contains = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Returns only the Medical Scribe jobs that contain the specified string. The search is not case sensitive.</p>
    pub fn set_job_name_contains(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_name_contains = input;
        self
    }
    /// <p>Returns only the Medical Scribe jobs that contain the specified string. The search is not case sensitive.</p>
    pub fn get_job_name_contains(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_name_contains
    }
    /// <p>If your <code>ListMedicalScribeJobs</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If your <code>ListMedicalScribeJobs</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If your <code>ListMedicalScribeJobs</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of Medical Scribe jobs to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of Medical Scribe jobs to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of Medical Scribe jobs to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListMedicalScribeJobsInput`](crate::operation::list_medical_scribe_jobs::ListMedicalScribeJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_medical_scribe_jobs::ListMedicalScribeJobsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_medical_scribe_jobs::ListMedicalScribeJobsInput {
            status: self.status,
            job_name_contains: self.job_name_contains,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
