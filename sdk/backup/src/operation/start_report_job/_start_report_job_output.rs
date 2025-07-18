// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartReportJobOutput {
    /// <p>The identifier of the report job. A unique, randomly generated, Unicode, UTF-8 encoded string that is at most 1,024 bytes long. The report job ID cannot be edited.</p>
    pub report_job_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartReportJobOutput {
    /// <p>The identifier of the report job. A unique, randomly generated, Unicode, UTF-8 encoded string that is at most 1,024 bytes long. The report job ID cannot be edited.</p>
    pub fn report_job_id(&self) -> ::std::option::Option<&str> {
        self.report_job_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartReportJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartReportJobOutput {
    /// Creates a new builder-style object to manufacture [`StartReportJobOutput`](crate::operation::start_report_job::StartReportJobOutput).
    pub fn builder() -> crate::operation::start_report_job::builders::StartReportJobOutputBuilder {
        crate::operation::start_report_job::builders::StartReportJobOutputBuilder::default()
    }
}

/// A builder for [`StartReportJobOutput`](crate::operation::start_report_job::StartReportJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartReportJobOutputBuilder {
    pub(crate) report_job_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartReportJobOutputBuilder {
    /// <p>The identifier of the report job. A unique, randomly generated, Unicode, UTF-8 encoded string that is at most 1,024 bytes long. The report job ID cannot be edited.</p>
    pub fn report_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.report_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the report job. A unique, randomly generated, Unicode, UTF-8 encoded string that is at most 1,024 bytes long. The report job ID cannot be edited.</p>
    pub fn set_report_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.report_job_id = input;
        self
    }
    /// <p>The identifier of the report job. A unique, randomly generated, Unicode, UTF-8 encoded string that is at most 1,024 bytes long. The report job ID cannot be edited.</p>
    pub fn get_report_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.report_job_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartReportJobOutput`](crate::operation::start_report_job::StartReportJobOutput).
    pub fn build(self) -> crate::operation::start_report_job::StartReportJobOutput {
        crate::operation::start_report_job::StartReportJobOutput {
            report_job_id: self.report_job_id,
            _request_id: self._request_id,
        }
    }
}
