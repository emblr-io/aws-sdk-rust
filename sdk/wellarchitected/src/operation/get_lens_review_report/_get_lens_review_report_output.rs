// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Output of a get lens review report call.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLensReviewReportOutput {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub workload_id: ::std::option::Option<::std::string::String>,
    /// <p>The milestone number.</p>
    /// <p>A workload can have a maximum of 100 milestones.</p>
    pub milestone_number: ::std::option::Option<i32>,
    /// <p>A report of a lens review.</p>
    pub lens_review_report: ::std::option::Option<crate::types::LensReviewReport>,
    _request_id: Option<String>,
}
impl GetLensReviewReportOutput {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn workload_id(&self) -> ::std::option::Option<&str> {
        self.workload_id.as_deref()
    }
    /// <p>The milestone number.</p>
    /// <p>A workload can have a maximum of 100 milestones.</p>
    pub fn milestone_number(&self) -> ::std::option::Option<i32> {
        self.milestone_number
    }
    /// <p>A report of a lens review.</p>
    pub fn lens_review_report(&self) -> ::std::option::Option<&crate::types::LensReviewReport> {
        self.lens_review_report.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetLensReviewReportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetLensReviewReportOutput {
    /// Creates a new builder-style object to manufacture [`GetLensReviewReportOutput`](crate::operation::get_lens_review_report::GetLensReviewReportOutput).
    pub fn builder() -> crate::operation::get_lens_review_report::builders::GetLensReviewReportOutputBuilder {
        crate::operation::get_lens_review_report::builders::GetLensReviewReportOutputBuilder::default()
    }
}

/// A builder for [`GetLensReviewReportOutput`](crate::operation::get_lens_review_report::GetLensReviewReportOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLensReviewReportOutputBuilder {
    pub(crate) workload_id: ::std::option::Option<::std::string::String>,
    pub(crate) milestone_number: ::std::option::Option<i32>,
    pub(crate) lens_review_report: ::std::option::Option<crate::types::LensReviewReport>,
    _request_id: Option<String>,
}
impl GetLensReviewReportOutputBuilder {
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn workload_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workload_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn set_workload_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workload_id = input;
        self
    }
    /// <p>The ID assigned to the workload. This ID is unique within an Amazon Web Services Region.</p>
    pub fn get_workload_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.workload_id
    }
    /// <p>The milestone number.</p>
    /// <p>A workload can have a maximum of 100 milestones.</p>
    pub fn milestone_number(mut self, input: i32) -> Self {
        self.milestone_number = ::std::option::Option::Some(input);
        self
    }
    /// <p>The milestone number.</p>
    /// <p>A workload can have a maximum of 100 milestones.</p>
    pub fn set_milestone_number(mut self, input: ::std::option::Option<i32>) -> Self {
        self.milestone_number = input;
        self
    }
    /// <p>The milestone number.</p>
    /// <p>A workload can have a maximum of 100 milestones.</p>
    pub fn get_milestone_number(&self) -> &::std::option::Option<i32> {
        &self.milestone_number
    }
    /// <p>A report of a lens review.</p>
    pub fn lens_review_report(mut self, input: crate::types::LensReviewReport) -> Self {
        self.lens_review_report = ::std::option::Option::Some(input);
        self
    }
    /// <p>A report of a lens review.</p>
    pub fn set_lens_review_report(mut self, input: ::std::option::Option<crate::types::LensReviewReport>) -> Self {
        self.lens_review_report = input;
        self
    }
    /// <p>A report of a lens review.</p>
    pub fn get_lens_review_report(&self) -> &::std::option::Option<crate::types::LensReviewReport> {
        &self.lens_review_report
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetLensReviewReportOutput`](crate::operation::get_lens_review_report::GetLensReviewReportOutput).
    pub fn build(self) -> crate::operation::get_lens_review_report::GetLensReviewReportOutput {
        crate::operation::get_lens_review_report::GetLensReviewReportOutput {
            workload_id: self.workload_id,
            milestone_number: self.milestone_number,
            lens_review_report: self.lens_review_report,
            _request_id: self._request_id,
        }
    }
}
