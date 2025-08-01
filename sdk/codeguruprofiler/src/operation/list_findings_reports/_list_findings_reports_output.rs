// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The structure representing the ListFindingsReportsResponse.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFindingsReportsOutput {
    /// <p>The list of analysis results summaries.</p>
    pub findings_report_summaries: ::std::vec::Vec<crate::types::FindingsReportSummary>,
    /// <p>The <code>nextToken</code> value to include in a future <code>ListFindingsReports</code> request. When the results of a <code>ListFindingsReports</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFindingsReportsOutput {
    /// <p>The list of analysis results summaries.</p>
    pub fn findings_report_summaries(&self) -> &[crate::types::FindingsReportSummary] {
        use std::ops::Deref;
        self.findings_report_summaries.deref()
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>ListFindingsReports</code> request. When the results of a <code>ListFindingsReports</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListFindingsReportsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListFindingsReportsOutput {
    /// Creates a new builder-style object to manufacture [`ListFindingsReportsOutput`](crate::operation::list_findings_reports::ListFindingsReportsOutput).
    pub fn builder() -> crate::operation::list_findings_reports::builders::ListFindingsReportsOutputBuilder {
        crate::operation::list_findings_reports::builders::ListFindingsReportsOutputBuilder::default()
    }
}

/// A builder for [`ListFindingsReportsOutput`](crate::operation::list_findings_reports::ListFindingsReportsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFindingsReportsOutputBuilder {
    pub(crate) findings_report_summaries: ::std::option::Option<::std::vec::Vec<crate::types::FindingsReportSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListFindingsReportsOutputBuilder {
    /// Appends an item to `findings_report_summaries`.
    ///
    /// To override the contents of this collection use [`set_findings_report_summaries`](Self::set_findings_report_summaries).
    ///
    /// <p>The list of analysis results summaries.</p>
    pub fn findings_report_summaries(mut self, input: crate::types::FindingsReportSummary) -> Self {
        let mut v = self.findings_report_summaries.unwrap_or_default();
        v.push(input);
        self.findings_report_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of analysis results summaries.</p>
    pub fn set_findings_report_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FindingsReportSummary>>) -> Self {
        self.findings_report_summaries = input;
        self
    }
    /// <p>The list of analysis results summaries.</p>
    pub fn get_findings_report_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FindingsReportSummary>> {
        &self.findings_report_summaries
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>ListFindingsReports</code> request. When the results of a <code>ListFindingsReports</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>ListFindingsReports</code> request. When the results of a <code>ListFindingsReports</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> value to include in a future <code>ListFindingsReports</code> request. When the results of a <code>ListFindingsReports</code> request exceed <code>maxResults</code>, this value can be used to retrieve the next page of results. This value is <code>null</code> when there are no more results to return.</p>
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
    /// Consumes the builder and constructs a [`ListFindingsReportsOutput`](crate::operation::list_findings_reports::ListFindingsReportsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`findings_report_summaries`](crate::operation::list_findings_reports::builders::ListFindingsReportsOutputBuilder::findings_report_summaries)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_findings_reports::ListFindingsReportsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_findings_reports::ListFindingsReportsOutput {
            findings_report_summaries: self.findings_report_summaries.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "findings_report_summaries",
                    "findings_report_summaries was not specified but it is required when building ListFindingsReportsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
