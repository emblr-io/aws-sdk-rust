// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetReportGroupTrendInput {
    /// <p>The ARN of the report group that contains the reports to analyze.</p>
    pub report_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The number of reports to analyze. This operation always retrieves the most recent reports.</p>
    /// <p>If this parameter is omitted, the most recent 100 reports are analyzed.</p>
    pub num_of_reports: ::std::option::Option<i32>,
    /// <p>The test report value to accumulate. This must be one of the following values:</p>
    /// <dl>
    /// <dt>
    /// Test reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// DURATION
    /// </dt>
    /// <dd>
    /// <p>Accumulate the test run times for the specified reports.</p>
    /// </dd>
    /// <dt>
    /// PASS_RATE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the percentage of tests that passed for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// TOTAL
    /// </dt>
    /// <dd>
    /// <p>Accumulate the total number of tests for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    /// <dl>
    /// <dt>
    /// Code coverage reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// BRANCH_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branch coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches missed values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the line coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines not covered values for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    pub trend_field: ::std::option::Option<crate::types::ReportGroupTrendFieldType>,
}
impl GetReportGroupTrendInput {
    /// <p>The ARN of the report group that contains the reports to analyze.</p>
    pub fn report_group_arn(&self) -> ::std::option::Option<&str> {
        self.report_group_arn.as_deref()
    }
    /// <p>The number of reports to analyze. This operation always retrieves the most recent reports.</p>
    /// <p>If this parameter is omitted, the most recent 100 reports are analyzed.</p>
    pub fn num_of_reports(&self) -> ::std::option::Option<i32> {
        self.num_of_reports
    }
    /// <p>The test report value to accumulate. This must be one of the following values:</p>
    /// <dl>
    /// <dt>
    /// Test reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// DURATION
    /// </dt>
    /// <dd>
    /// <p>Accumulate the test run times for the specified reports.</p>
    /// </dd>
    /// <dt>
    /// PASS_RATE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the percentage of tests that passed for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// TOTAL
    /// </dt>
    /// <dd>
    /// <p>Accumulate the total number of tests for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    /// <dl>
    /// <dt>
    /// Code coverage reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// BRANCH_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branch coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches missed values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the line coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines not covered values for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    pub fn trend_field(&self) -> ::std::option::Option<&crate::types::ReportGroupTrendFieldType> {
        self.trend_field.as_ref()
    }
}
impl GetReportGroupTrendInput {
    /// Creates a new builder-style object to manufacture [`GetReportGroupTrendInput`](crate::operation::get_report_group_trend::GetReportGroupTrendInput).
    pub fn builder() -> crate::operation::get_report_group_trend::builders::GetReportGroupTrendInputBuilder {
        crate::operation::get_report_group_trend::builders::GetReportGroupTrendInputBuilder::default()
    }
}

/// A builder for [`GetReportGroupTrendInput`](crate::operation::get_report_group_trend::GetReportGroupTrendInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetReportGroupTrendInputBuilder {
    pub(crate) report_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) num_of_reports: ::std::option::Option<i32>,
    pub(crate) trend_field: ::std::option::Option<crate::types::ReportGroupTrendFieldType>,
}
impl GetReportGroupTrendInputBuilder {
    /// <p>The ARN of the report group that contains the reports to analyze.</p>
    /// This field is required.
    pub fn report_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.report_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the report group that contains the reports to analyze.</p>
    pub fn set_report_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.report_group_arn = input;
        self
    }
    /// <p>The ARN of the report group that contains the reports to analyze.</p>
    pub fn get_report_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.report_group_arn
    }
    /// <p>The number of reports to analyze. This operation always retrieves the most recent reports.</p>
    /// <p>If this parameter is omitted, the most recent 100 reports are analyzed.</p>
    pub fn num_of_reports(mut self, input: i32) -> Self {
        self.num_of_reports = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of reports to analyze. This operation always retrieves the most recent reports.</p>
    /// <p>If this parameter is omitted, the most recent 100 reports are analyzed.</p>
    pub fn set_num_of_reports(mut self, input: ::std::option::Option<i32>) -> Self {
        self.num_of_reports = input;
        self
    }
    /// <p>The number of reports to analyze. This operation always retrieves the most recent reports.</p>
    /// <p>If this parameter is omitted, the most recent 100 reports are analyzed.</p>
    pub fn get_num_of_reports(&self) -> &::std::option::Option<i32> {
        &self.num_of_reports
    }
    /// <p>The test report value to accumulate. This must be one of the following values:</p>
    /// <dl>
    /// <dt>
    /// Test reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// DURATION
    /// </dt>
    /// <dd>
    /// <p>Accumulate the test run times for the specified reports.</p>
    /// </dd>
    /// <dt>
    /// PASS_RATE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the percentage of tests that passed for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// TOTAL
    /// </dt>
    /// <dd>
    /// <p>Accumulate the total number of tests for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    /// <dl>
    /// <dt>
    /// Code coverage reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// BRANCH_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branch coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches missed values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the line coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines not covered values for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    /// This field is required.
    pub fn trend_field(mut self, input: crate::types::ReportGroupTrendFieldType) -> Self {
        self.trend_field = ::std::option::Option::Some(input);
        self
    }
    /// <p>The test report value to accumulate. This must be one of the following values:</p>
    /// <dl>
    /// <dt>
    /// Test reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// DURATION
    /// </dt>
    /// <dd>
    /// <p>Accumulate the test run times for the specified reports.</p>
    /// </dd>
    /// <dt>
    /// PASS_RATE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the percentage of tests that passed for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// TOTAL
    /// </dt>
    /// <dd>
    /// <p>Accumulate the total number of tests for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    /// <dl>
    /// <dt>
    /// Code coverage reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// BRANCH_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branch coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches missed values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the line coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines not covered values for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    pub fn set_trend_field(mut self, input: ::std::option::Option<crate::types::ReportGroupTrendFieldType>) -> Self {
        self.trend_field = input;
        self
    }
    /// <p>The test report value to accumulate. This must be one of the following values:</p>
    /// <dl>
    /// <dt>
    /// Test reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// DURATION
    /// </dt>
    /// <dd>
    /// <p>Accumulate the test run times for the specified reports.</p>
    /// </dd>
    /// <dt>
    /// PASS_RATE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the percentage of tests that passed for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// TOTAL
    /// </dt>
    /// <dd>
    /// <p>Accumulate the total number of tests for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    /// <dl>
    /// <dt>
    /// Code coverage reports:
    /// </dt>
    /// <dd>
    /// <dl>
    /// <dt>
    /// BRANCH_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branch coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// BRANCHES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the branches missed values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE
    /// </dt>
    /// <dd>
    /// <p>Accumulate the line coverage percentages for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_COVERED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines covered values for the specified test reports.</p>
    /// </dd>
    /// <dt>
    /// LINES_MISSED
    /// </dt>
    /// <dd>
    /// <p>Accumulate the lines not covered values for the specified test reports.</p>
    /// </dd>
    /// </dl>
    /// </dd>
    /// </dl>
    pub fn get_trend_field(&self) -> &::std::option::Option<crate::types::ReportGroupTrendFieldType> {
        &self.trend_field
    }
    /// Consumes the builder and constructs a [`GetReportGroupTrendInput`](crate::operation::get_report_group_trend::GetReportGroupTrendInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_report_group_trend::GetReportGroupTrendInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_report_group_trend::GetReportGroupTrendInput {
            report_group_arn: self.report_group_arn,
            num_of_reports: self.num_of_reports,
            trend_field: self.trend_field,
        })
    }
}
