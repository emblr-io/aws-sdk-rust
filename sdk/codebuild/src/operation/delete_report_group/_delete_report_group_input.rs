// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteReportGroupInput {
    /// <p>The ARN of the report group to delete.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>If <code>true</code>, deletes any reports that belong to a report group before deleting the report group.</p>
    /// <p>If <code>false</code>, you must delete any reports in the report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ListReportsForReportGroup.html">ListReportsForReportGroup</a> to get the reports in a report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_DeleteReport.html">DeleteReport</a> to delete the reports. If you call <code>DeleteReportGroup</code> for a report group that contains one or more reports, an exception is thrown.</p>
    pub delete_reports: ::std::option::Option<bool>,
}
impl DeleteReportGroupInput {
    /// <p>The ARN of the report group to delete.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>If <code>true</code>, deletes any reports that belong to a report group before deleting the report group.</p>
    /// <p>If <code>false</code>, you must delete any reports in the report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ListReportsForReportGroup.html">ListReportsForReportGroup</a> to get the reports in a report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_DeleteReport.html">DeleteReport</a> to delete the reports. If you call <code>DeleteReportGroup</code> for a report group that contains one or more reports, an exception is thrown.</p>
    pub fn delete_reports(&self) -> ::std::option::Option<bool> {
        self.delete_reports
    }
}
impl DeleteReportGroupInput {
    /// Creates a new builder-style object to manufacture [`DeleteReportGroupInput`](crate::operation::delete_report_group::DeleteReportGroupInput).
    pub fn builder() -> crate::operation::delete_report_group::builders::DeleteReportGroupInputBuilder {
        crate::operation::delete_report_group::builders::DeleteReportGroupInputBuilder::default()
    }
}

/// A builder for [`DeleteReportGroupInput`](crate::operation::delete_report_group::DeleteReportGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteReportGroupInputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) delete_reports: ::std::option::Option<bool>,
}
impl DeleteReportGroupInputBuilder {
    /// <p>The ARN of the report group to delete.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the report group to delete.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the report group to delete.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>If <code>true</code>, deletes any reports that belong to a report group before deleting the report group.</p>
    /// <p>If <code>false</code>, you must delete any reports in the report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ListReportsForReportGroup.html">ListReportsForReportGroup</a> to get the reports in a report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_DeleteReport.html">DeleteReport</a> to delete the reports. If you call <code>DeleteReportGroup</code> for a report group that contains one or more reports, an exception is thrown.</p>
    pub fn delete_reports(mut self, input: bool) -> Self {
        self.delete_reports = ::std::option::Option::Some(input);
        self
    }
    /// <p>If <code>true</code>, deletes any reports that belong to a report group before deleting the report group.</p>
    /// <p>If <code>false</code>, you must delete any reports in the report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ListReportsForReportGroup.html">ListReportsForReportGroup</a> to get the reports in a report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_DeleteReport.html">DeleteReport</a> to delete the reports. If you call <code>DeleteReportGroup</code> for a report group that contains one or more reports, an exception is thrown.</p>
    pub fn set_delete_reports(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_reports = input;
        self
    }
    /// <p>If <code>true</code>, deletes any reports that belong to a report group before deleting the report group.</p>
    /// <p>If <code>false</code>, you must delete any reports in the report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_ListReportsForReportGroup.html">ListReportsForReportGroup</a> to get the reports in a report group. Use <a href="https://docs.aws.amazon.com/codebuild/latest/APIReference/API_DeleteReport.html">DeleteReport</a> to delete the reports. If you call <code>DeleteReportGroup</code> for a report group that contains one or more reports, an exception is thrown.</p>
    pub fn get_delete_reports(&self) -> &::std::option::Option<bool> {
        &self.delete_reports
    }
    /// Consumes the builder and constructs a [`DeleteReportGroupInput`](crate::operation::delete_report_group::DeleteReportGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_report_group::DeleteReportGroupInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_report_group::DeleteReportGroupInput {
            arn: self.arn,
            delete_reports: self.delete_reports,
        })
    }
}
