// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request body for ListBackendJobs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListBackendJobsInput {
    /// <p>The app ID.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the backend environment.</p>
    pub backend_environment_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID for the job.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results that you want in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Filters the list of response objects to include only those with the specified operation name.</p>
    pub operation: ::std::option::Option<::std::string::String>,
    /// <p>Filters the list of response objects to include only those with the specified status.</p>
    pub status: ::std::option::Option<::std::string::String>,
}
impl ListBackendJobsInput {
    /// <p>The app ID.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>The name of the backend environment.</p>
    pub fn backend_environment_name(&self) -> ::std::option::Option<&str> {
        self.backend_environment_name.as_deref()
    }
    /// <p>The ID for the job.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The maximum number of results that you want in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Filters the list of response objects to include only those with the specified operation name.</p>
    pub fn operation(&self) -> ::std::option::Option<&str> {
        self.operation.as_deref()
    }
    /// <p>Filters the list of response objects to include only those with the specified status.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
}
impl ListBackendJobsInput {
    /// Creates a new builder-style object to manufacture [`ListBackendJobsInput`](crate::operation::list_backend_jobs::ListBackendJobsInput).
    pub fn builder() -> crate::operation::list_backend_jobs::builders::ListBackendJobsInputBuilder {
        crate::operation::list_backend_jobs::builders::ListBackendJobsInputBuilder::default()
    }
}

/// A builder for [`ListBackendJobsInput`](crate::operation::list_backend_jobs::ListBackendJobsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListBackendJobsInputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) backend_environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) operation: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
}
impl ListBackendJobsInputBuilder {
    /// <p>The app ID.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The app ID.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The app ID.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The name of the backend environment.</p>
    /// This field is required.
    pub fn backend_environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backend_environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the backend environment.</p>
    pub fn set_backend_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backend_environment_name = input;
        self
    }
    /// <p>The name of the backend environment.</p>
    pub fn get_backend_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.backend_environment_name
    }
    /// <p>The ID for the job.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID for the job.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>The ID for the job.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The maximum number of results that you want in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that you want in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that you want in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Filters the list of response objects to include only those with the specified operation name.</p>
    pub fn operation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters the list of response objects to include only those with the specified operation name.</p>
    pub fn set_operation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation = input;
        self
    }
    /// <p>Filters the list of response objects to include only those with the specified operation name.</p>
    pub fn get_operation(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation
    }
    /// <p>Filters the list of response objects to include only those with the specified status.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters the list of response objects to include only those with the specified status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>Filters the list of response objects to include only those with the specified status.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// Consumes the builder and constructs a [`ListBackendJobsInput`](crate::operation::list_backend_jobs::ListBackendJobsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_backend_jobs::ListBackendJobsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_backend_jobs::ListBackendJobsInput {
            app_id: self.app_id,
            backend_environment_name: self.backend_environment_name,
            job_id: self.job_id,
            max_results: self.max_results,
            next_token: self.next_token,
            operation: self.operation,
            status: self.status,
        })
    }
}
