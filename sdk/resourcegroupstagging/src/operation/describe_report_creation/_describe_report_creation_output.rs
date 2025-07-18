// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeReportCreationOutput {
    /// <p>Reports the status of the operation.</p>
    /// <p>The operation status can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> - Report creation is in progress.</p></li>
    /// <li>
    /// <p><code>SUCCEEDED</code> - Report creation is complete. You can open the report from the Amazon S3 bucket that you specified when you ran <code>StartReportCreation</code>.</p></li>
    /// <li>
    /// <p><code>FAILED</code> - Report creation timed out or the Amazon S3 bucket is not accessible.</p></li>
    /// <li>
    /// <p><code>NO REPORT</code> - No report was generated in the last 90 days.</p></li>
    /// </ul>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The path to the Amazon S3 bucket where the report was stored on creation.</p>
    pub s3_location: ::std::option::Option<::std::string::String>,
    /// <p>The date and time that the report was started.</p>
    pub start_date: ::std::option::Option<::std::string::String>,
    /// <p>Details of the common errors that all operations return.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeReportCreationOutput {
    /// <p>Reports the status of the operation.</p>
    /// <p>The operation status can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> - Report creation is in progress.</p></li>
    /// <li>
    /// <p><code>SUCCEEDED</code> - Report creation is complete. You can open the report from the Amazon S3 bucket that you specified when you ran <code>StartReportCreation</code>.</p></li>
    /// <li>
    /// <p><code>FAILED</code> - Report creation timed out or the Amazon S3 bucket is not accessible.</p></li>
    /// <li>
    /// <p><code>NO REPORT</code> - No report was generated in the last 90 days.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The path to the Amazon S3 bucket where the report was stored on creation.</p>
    pub fn s3_location(&self) -> ::std::option::Option<&str> {
        self.s3_location.as_deref()
    }
    /// <p>The date and time that the report was started.</p>
    pub fn start_date(&self) -> ::std::option::Option<&str> {
        self.start_date.as_deref()
    }
    /// <p>Details of the common errors that all operations return.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeReportCreationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeReportCreationOutput {
    /// Creates a new builder-style object to manufacture [`DescribeReportCreationOutput`](crate::operation::describe_report_creation::DescribeReportCreationOutput).
    pub fn builder() -> crate::operation::describe_report_creation::builders::DescribeReportCreationOutputBuilder {
        crate::operation::describe_report_creation::builders::DescribeReportCreationOutputBuilder::default()
    }
}

/// A builder for [`DescribeReportCreationOutput`](crate::operation::describe_report_creation::DescribeReportCreationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeReportCreationOutputBuilder {
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) s3_location: ::std::option::Option<::std::string::String>,
    pub(crate) start_date: ::std::option::Option<::std::string::String>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeReportCreationOutputBuilder {
    /// <p>Reports the status of the operation.</p>
    /// <p>The operation status can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> - Report creation is in progress.</p></li>
    /// <li>
    /// <p><code>SUCCEEDED</code> - Report creation is complete. You can open the report from the Amazon S3 bucket that you specified when you ran <code>StartReportCreation</code>.</p></li>
    /// <li>
    /// <p><code>FAILED</code> - Report creation timed out or the Amazon S3 bucket is not accessible.</p></li>
    /// <li>
    /// <p><code>NO REPORT</code> - No report was generated in the last 90 days.</p></li>
    /// </ul>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Reports the status of the operation.</p>
    /// <p>The operation status can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> - Report creation is in progress.</p></li>
    /// <li>
    /// <p><code>SUCCEEDED</code> - Report creation is complete. You can open the report from the Amazon S3 bucket that you specified when you ran <code>StartReportCreation</code>.</p></li>
    /// <li>
    /// <p><code>FAILED</code> - Report creation timed out or the Amazon S3 bucket is not accessible.</p></li>
    /// <li>
    /// <p><code>NO REPORT</code> - No report was generated in the last 90 days.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>Reports the status of the operation.</p>
    /// <p>The operation status can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>RUNNING</code> - Report creation is in progress.</p></li>
    /// <li>
    /// <p><code>SUCCEEDED</code> - Report creation is complete. You can open the report from the Amazon S3 bucket that you specified when you ran <code>StartReportCreation</code>.</p></li>
    /// <li>
    /// <p><code>FAILED</code> - Report creation timed out or the Amazon S3 bucket is not accessible.</p></li>
    /// <li>
    /// <p><code>NO REPORT</code> - No report was generated in the last 90 days.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The path to the Amazon S3 bucket where the report was stored on creation.</p>
    pub fn s3_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path to the Amazon S3 bucket where the report was stored on creation.</p>
    pub fn set_s3_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_location = input;
        self
    }
    /// <p>The path to the Amazon S3 bucket where the report was stored on creation.</p>
    pub fn get_s3_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_location
    }
    /// <p>The date and time that the report was started.</p>
    pub fn start_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.start_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time that the report was started.</p>
    pub fn set_start_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.start_date = input;
        self
    }
    /// <p>The date and time that the report was started.</p>
    pub fn get_start_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.start_date
    }
    /// <p>Details of the common errors that all operations return.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Details of the common errors that all operations return.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>Details of the common errors that all operations return.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeReportCreationOutput`](crate::operation::describe_report_creation::DescribeReportCreationOutput).
    pub fn build(self) -> crate::operation::describe_report_creation::DescribeReportCreationOutput {
        crate::operation::describe_report_creation::DescribeReportCreationOutput {
            status: self.status,
            s3_location: self.s3_location,
            start_date: self.start_date,
            error_message: self.error_message,
            _request_id: self._request_id,
        }
    }
}
