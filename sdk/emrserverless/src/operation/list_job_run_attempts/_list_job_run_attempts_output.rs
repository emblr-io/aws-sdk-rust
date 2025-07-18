// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListJobRunAttemptsOutput {
    /// <p>The array of the listed job run attempt objects.</p>
    pub job_run_attempts: ::std::vec::Vec<crate::types::JobRunAttemptSummary>,
    /// <p>The output displays the token for the next set of application results. This is required for pagination and is available as a response of the previous request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListJobRunAttemptsOutput {
    /// <p>The array of the listed job run attempt objects.</p>
    pub fn job_run_attempts(&self) -> &[crate::types::JobRunAttemptSummary] {
        use std::ops::Deref;
        self.job_run_attempts.deref()
    }
    /// <p>The output displays the token for the next set of application results. This is required for pagination and is available as a response of the previous request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListJobRunAttemptsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListJobRunAttemptsOutput {
    /// Creates a new builder-style object to manufacture [`ListJobRunAttemptsOutput`](crate::operation::list_job_run_attempts::ListJobRunAttemptsOutput).
    pub fn builder() -> crate::operation::list_job_run_attempts::builders::ListJobRunAttemptsOutputBuilder {
        crate::operation::list_job_run_attempts::builders::ListJobRunAttemptsOutputBuilder::default()
    }
}

/// A builder for [`ListJobRunAttemptsOutput`](crate::operation::list_job_run_attempts::ListJobRunAttemptsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListJobRunAttemptsOutputBuilder {
    pub(crate) job_run_attempts: ::std::option::Option<::std::vec::Vec<crate::types::JobRunAttemptSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListJobRunAttemptsOutputBuilder {
    /// Appends an item to `job_run_attempts`.
    ///
    /// To override the contents of this collection use [`set_job_run_attempts`](Self::set_job_run_attempts).
    ///
    /// <p>The array of the listed job run attempt objects.</p>
    pub fn job_run_attempts(mut self, input: crate::types::JobRunAttemptSummary) -> Self {
        let mut v = self.job_run_attempts.unwrap_or_default();
        v.push(input);
        self.job_run_attempts = ::std::option::Option::Some(v);
        self
    }
    /// <p>The array of the listed job run attempt objects.</p>
    pub fn set_job_run_attempts(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::JobRunAttemptSummary>>) -> Self {
        self.job_run_attempts = input;
        self
    }
    /// <p>The array of the listed job run attempt objects.</p>
    pub fn get_job_run_attempts(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::JobRunAttemptSummary>> {
        &self.job_run_attempts
    }
    /// <p>The output displays the token for the next set of application results. This is required for pagination and is available as a response of the previous request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The output displays the token for the next set of application results. This is required for pagination and is available as a response of the previous request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The output displays the token for the next set of application results. This is required for pagination and is available as a response of the previous request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListJobRunAttemptsOutput`](crate::operation::list_job_run_attempts::ListJobRunAttemptsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`job_run_attempts`](crate::operation::list_job_run_attempts::builders::ListJobRunAttemptsOutputBuilder::job_run_attempts)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_job_run_attempts::ListJobRunAttemptsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_job_run_attempts::ListJobRunAttemptsOutput {
            job_run_attempts: self.job_run_attempts.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "job_run_attempts",
                    "job_run_attempts was not specified but it is required when building ListJobRunAttemptsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
