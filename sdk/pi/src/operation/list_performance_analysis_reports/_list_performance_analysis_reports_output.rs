// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPerformanceAnalysisReportsOutput {
    /// <p>List of reports including the report identifier, start and end time, creation time, and status.</p>
    pub analysis_reports: ::std::option::Option<::std::vec::Vec<crate::types::AnalysisReportSummary>>,
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxResults</code>.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPerformanceAnalysisReportsOutput {
    /// <p>List of reports including the report identifier, start and end time, creation time, and status.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.analysis_reports.is_none()`.
    pub fn analysis_reports(&self) -> &[crate::types::AnalysisReportSummary] {
        self.analysis_reports.as_deref().unwrap_or_default()
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxResults</code>.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPerformanceAnalysisReportsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPerformanceAnalysisReportsOutput {
    /// Creates a new builder-style object to manufacture [`ListPerformanceAnalysisReportsOutput`](crate::operation::list_performance_analysis_reports::ListPerformanceAnalysisReportsOutput).
    pub fn builder() -> crate::operation::list_performance_analysis_reports::builders::ListPerformanceAnalysisReportsOutputBuilder {
        crate::operation::list_performance_analysis_reports::builders::ListPerformanceAnalysisReportsOutputBuilder::default()
    }
}

/// A builder for [`ListPerformanceAnalysisReportsOutput`](crate::operation::list_performance_analysis_reports::ListPerformanceAnalysisReportsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPerformanceAnalysisReportsOutputBuilder {
    pub(crate) analysis_reports: ::std::option::Option<::std::vec::Vec<crate::types::AnalysisReportSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPerformanceAnalysisReportsOutputBuilder {
    /// Appends an item to `analysis_reports`.
    ///
    /// To override the contents of this collection use [`set_analysis_reports`](Self::set_analysis_reports).
    ///
    /// <p>List of reports including the report identifier, start and end time, creation time, and status.</p>
    pub fn analysis_reports(mut self, input: crate::types::AnalysisReportSummary) -> Self {
        let mut v = self.analysis_reports.unwrap_or_default();
        v.push(input);
        self.analysis_reports = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of reports including the report identifier, start and end time, creation time, and status.</p>
    pub fn set_analysis_reports(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AnalysisReportSummary>>) -> Self {
        self.analysis_reports = input;
        self
    }
    /// <p>List of reports including the report identifier, start and end time, creation time, and status.</p>
    pub fn get_analysis_reports(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AnalysisReportSummary>> {
        &self.analysis_reports
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxResults</code>.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxResults</code>.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the token, up to the value specified by <code>MaxResults</code>.</p>
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
    /// Consumes the builder and constructs a [`ListPerformanceAnalysisReportsOutput`](crate::operation::list_performance_analysis_reports::ListPerformanceAnalysisReportsOutput).
    pub fn build(self) -> crate::operation::list_performance_analysis_reports::ListPerformanceAnalysisReportsOutput {
        crate::operation::list_performance_analysis_reports::ListPerformanceAnalysisReportsOutput {
            analysis_reports: self.analysis_reports,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
