// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The CreateJobResponse structure.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateJobOutput {
    /// <p>A section of the response body that provides information about the job that is created.</p>
    pub job: ::std::option::Option<crate::types::Job>,
    _request_id: Option<String>,
}
impl CreateJobOutput {
    /// <p>A section of the response body that provides information about the job that is created.</p>
    pub fn job(&self) -> ::std::option::Option<&crate::types::Job> {
        self.job.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateJobOutput {
    /// Creates a new builder-style object to manufacture [`CreateJobOutput`](crate::operation::create_job::CreateJobOutput).
    pub fn builder() -> crate::operation::create_job::builders::CreateJobOutputBuilder {
        crate::operation::create_job::builders::CreateJobOutputBuilder::default()
    }
}

/// A builder for [`CreateJobOutput`](crate::operation::create_job::CreateJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateJobOutputBuilder {
    pub(crate) job: ::std::option::Option<crate::types::Job>,
    _request_id: Option<String>,
}
impl CreateJobOutputBuilder {
    /// <p>A section of the response body that provides information about the job that is created.</p>
    pub fn job(mut self, input: crate::types::Job) -> Self {
        self.job = ::std::option::Option::Some(input);
        self
    }
    /// <p>A section of the response body that provides information about the job that is created.</p>
    pub fn set_job(mut self, input: ::std::option::Option<crate::types::Job>) -> Self {
        self.job = input;
        self
    }
    /// <p>A section of the response body that provides information about the job that is created.</p>
    pub fn get_job(&self) -> &::std::option::Option<crate::types::Job> {
        &self.job
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateJobOutput`](crate::operation::create_job::CreateJobOutput).
    pub fn build(self) -> crate::operation::create_job::CreateJobOutput {
        crate::operation::create_job::CreateJobOutput {
            job: self.job,
            _request_id: self._request_id,
        }
    }
}
