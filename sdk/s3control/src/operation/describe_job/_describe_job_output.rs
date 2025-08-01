// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeJobOutput {
    /// <p>Contains the configuration parameters and status for the job specified in the <code>Describe Job</code> request.</p>
    pub job: ::std::option::Option<crate::types::JobDescriptor>,
    _request_id: Option<String>,
}
impl DescribeJobOutput {
    /// <p>Contains the configuration parameters and status for the job specified in the <code>Describe Job</code> request.</p>
    pub fn job(&self) -> ::std::option::Option<&crate::types::JobDescriptor> {
        self.job.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeJobOutput {
    /// Creates a new builder-style object to manufacture [`DescribeJobOutput`](crate::operation::describe_job::DescribeJobOutput).
    pub fn builder() -> crate::operation::describe_job::builders::DescribeJobOutputBuilder {
        crate::operation::describe_job::builders::DescribeJobOutputBuilder::default()
    }
}

/// A builder for [`DescribeJobOutput`](crate::operation::describe_job::DescribeJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeJobOutputBuilder {
    pub(crate) job: ::std::option::Option<crate::types::JobDescriptor>,
    _request_id: Option<String>,
}
impl DescribeJobOutputBuilder {
    /// <p>Contains the configuration parameters and status for the job specified in the <code>Describe Job</code> request.</p>
    pub fn job(mut self, input: crate::types::JobDescriptor) -> Self {
        self.job = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the configuration parameters and status for the job specified in the <code>Describe Job</code> request.</p>
    pub fn set_job(mut self, input: ::std::option::Option<crate::types::JobDescriptor>) -> Self {
        self.job = input;
        self
    }
    /// <p>Contains the configuration parameters and status for the job specified in the <code>Describe Job</code> request.</p>
    pub fn get_job(&self) -> &::std::option::Option<crate::types::JobDescriptor> {
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
    /// Consumes the builder and constructs a [`DescribeJobOutput`](crate::operation::describe_job::DescribeJobOutput).
    pub fn build(self) -> crate::operation::describe_job::DescribeJobOutput {
        crate::operation::describe_job::DescribeJobOutput {
            job: self.job,
            _request_id: self._request_id,
        }
    }
}
