// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAssessmentReportOutput {
    /// <p>Specifies the status of the request to generate an assessment report.</p>
    pub status: crate::types::ReportStatus,
    /// <p>Specifies the URL where you can find the generated assessment report. This parameter is only returned if the report is successfully generated.</p>
    pub url: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetAssessmentReportOutput {
    /// <p>Specifies the status of the request to generate an assessment report.</p>
    pub fn status(&self) -> &crate::types::ReportStatus {
        &self.status
    }
    /// <p>Specifies the URL where you can find the generated assessment report. This parameter is only returned if the report is successfully generated.</p>
    pub fn url(&self) -> ::std::option::Option<&str> {
        self.url.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetAssessmentReportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAssessmentReportOutput {
    /// Creates a new builder-style object to manufacture [`GetAssessmentReportOutput`](crate::operation::get_assessment_report::GetAssessmentReportOutput).
    pub fn builder() -> crate::operation::get_assessment_report::builders::GetAssessmentReportOutputBuilder {
        crate::operation::get_assessment_report::builders::GetAssessmentReportOutputBuilder::default()
    }
}

/// A builder for [`GetAssessmentReportOutput`](crate::operation::get_assessment_report::GetAssessmentReportOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAssessmentReportOutputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::ReportStatus>,
    pub(crate) url: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetAssessmentReportOutputBuilder {
    /// <p>Specifies the status of the request to generate an assessment report.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::ReportStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the status of the request to generate an assessment report.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ReportStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Specifies the status of the request to generate an assessment report.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ReportStatus> {
        &self.status
    }
    /// <p>Specifies the URL where you can find the generated assessment report. This parameter is only returned if the report is successfully generated.</p>
    pub fn url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the URL where you can find the generated assessment report. This parameter is only returned if the report is successfully generated.</p>
    pub fn set_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.url = input;
        self
    }
    /// <p>Specifies the URL where you can find the generated assessment report. This parameter is only returned if the report is successfully generated.</p>
    pub fn get_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.url
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAssessmentReportOutput`](crate::operation::get_assessment_report::GetAssessmentReportOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::operation::get_assessment_report::builders::GetAssessmentReportOutputBuilder::status)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_assessment_report::GetAssessmentReportOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_assessment_report::GetAssessmentReportOutput {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetAssessmentReportOutput",
                )
            })?,
            url: self.url,
            _request_id: self._request_id,
        })
    }
}
