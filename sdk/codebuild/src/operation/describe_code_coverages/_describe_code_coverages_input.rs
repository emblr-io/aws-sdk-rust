// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCodeCoveragesInput {
    /// <p>The ARN of the report for which test cases are returned.</p>
    pub report_arn: ::std::option::Option<::std::string::String>,
    /// <p>The <code>nextToken</code> value returned from a previous call to <code>DescribeCodeCoverages</code>. This specifies the next item to return. To return the beginning of the list, exclude this parameter.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>Specifies if the results are sorted in ascending or descending order.</p>
    pub sort_order: ::std::option::Option<crate::types::SortOrderType>,
    /// <p>Specifies how the results are sorted. Possible values are:</p>
    /// <dl>
    /// <dt>
    /// FILE_PATH
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by file path.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE_PERCENTAGE
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by the percentage of lines that are covered.</p>
    /// </dd>
    /// </dl>
    pub sort_by: ::std::option::Option<crate::types::ReportCodeCoverageSortByType>,
    /// <p>The minimum line coverage percentage to report.</p>
    pub min_line_coverage_percentage: ::std::option::Option<f64>,
    /// <p>The maximum line coverage percentage to report.</p>
    pub max_line_coverage_percentage: ::std::option::Option<f64>,
}
impl DescribeCodeCoveragesInput {
    /// <p>The ARN of the report for which test cases are returned.</p>
    pub fn report_arn(&self) -> ::std::option::Option<&str> {
        self.report_arn.as_deref()
    }
    /// <p>The <code>nextToken</code> value returned from a previous call to <code>DescribeCodeCoverages</code>. This specifies the next item to return. To return the beginning of the list, exclude this parameter.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>Specifies if the results are sorted in ascending or descending order.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::SortOrderType> {
        self.sort_order.as_ref()
    }
    /// <p>Specifies how the results are sorted. Possible values are:</p>
    /// <dl>
    /// <dt>
    /// FILE_PATH
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by file path.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE_PERCENTAGE
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by the percentage of lines that are covered.</p>
    /// </dd>
    /// </dl>
    pub fn sort_by(&self) -> ::std::option::Option<&crate::types::ReportCodeCoverageSortByType> {
        self.sort_by.as_ref()
    }
    /// <p>The minimum line coverage percentage to report.</p>
    pub fn min_line_coverage_percentage(&self) -> ::std::option::Option<f64> {
        self.min_line_coverage_percentage
    }
    /// <p>The maximum line coverage percentage to report.</p>
    pub fn max_line_coverage_percentage(&self) -> ::std::option::Option<f64> {
        self.max_line_coverage_percentage
    }
}
impl DescribeCodeCoveragesInput {
    /// Creates a new builder-style object to manufacture [`DescribeCodeCoveragesInput`](crate::operation::describe_code_coverages::DescribeCodeCoveragesInput).
    pub fn builder() -> crate::operation::describe_code_coverages::builders::DescribeCodeCoveragesInputBuilder {
        crate::operation::describe_code_coverages::builders::DescribeCodeCoveragesInputBuilder::default()
    }
}

/// A builder for [`DescribeCodeCoveragesInput`](crate::operation::describe_code_coverages::DescribeCodeCoveragesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCodeCoveragesInputBuilder {
    pub(crate) report_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) sort_order: ::std::option::Option<crate::types::SortOrderType>,
    pub(crate) sort_by: ::std::option::Option<crate::types::ReportCodeCoverageSortByType>,
    pub(crate) min_line_coverage_percentage: ::std::option::Option<f64>,
    pub(crate) max_line_coverage_percentage: ::std::option::Option<f64>,
}
impl DescribeCodeCoveragesInputBuilder {
    /// <p>The ARN of the report for which test cases are returned.</p>
    /// This field is required.
    pub fn report_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.report_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the report for which test cases are returned.</p>
    pub fn set_report_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.report_arn = input;
        self
    }
    /// <p>The ARN of the report for which test cases are returned.</p>
    pub fn get_report_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.report_arn
    }
    /// <p>The <code>nextToken</code> value returned from a previous call to <code>DescribeCodeCoverages</code>. This specifies the next item to return. To return the beginning of the list, exclude this parameter.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>nextToken</code> value returned from a previous call to <code>DescribeCodeCoverages</code>. This specifies the next item to return. To return the beginning of the list, exclude this parameter.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The <code>nextToken</code> value returned from a previous call to <code>DescribeCodeCoverages</code>. This specifies the next item to return. To return the beginning of the list, exclude this parameter.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>Specifies if the results are sorted in ascending or descending order.</p>
    pub fn sort_order(mut self, input: crate::types::SortOrderType) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if the results are sorted in ascending or descending order.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::SortOrderType>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>Specifies if the results are sorted in ascending or descending order.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::SortOrderType> {
        &self.sort_order
    }
    /// <p>Specifies how the results are sorted. Possible values are:</p>
    /// <dl>
    /// <dt>
    /// FILE_PATH
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by file path.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE_PERCENTAGE
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by the percentage of lines that are covered.</p>
    /// </dd>
    /// </dl>
    pub fn sort_by(mut self, input: crate::types::ReportCodeCoverageSortByType) -> Self {
        self.sort_by = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies how the results are sorted. Possible values are:</p>
    /// <dl>
    /// <dt>
    /// FILE_PATH
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by file path.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE_PERCENTAGE
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by the percentage of lines that are covered.</p>
    /// </dd>
    /// </dl>
    pub fn set_sort_by(mut self, input: ::std::option::Option<crate::types::ReportCodeCoverageSortByType>) -> Self {
        self.sort_by = input;
        self
    }
    /// <p>Specifies how the results are sorted. Possible values are:</p>
    /// <dl>
    /// <dt>
    /// FILE_PATH
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by file path.</p>
    /// </dd>
    /// <dt>
    /// LINE_COVERAGE_PERCENTAGE
    /// </dt>
    /// <dd>
    /// <p>The results are sorted by the percentage of lines that are covered.</p>
    /// </dd>
    /// </dl>
    pub fn get_sort_by(&self) -> &::std::option::Option<crate::types::ReportCodeCoverageSortByType> {
        &self.sort_by
    }
    /// <p>The minimum line coverage percentage to report.</p>
    pub fn min_line_coverage_percentage(mut self, input: f64) -> Self {
        self.min_line_coverage_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum line coverage percentage to report.</p>
    pub fn set_min_line_coverage_percentage(mut self, input: ::std::option::Option<f64>) -> Self {
        self.min_line_coverage_percentage = input;
        self
    }
    /// <p>The minimum line coverage percentage to report.</p>
    pub fn get_min_line_coverage_percentage(&self) -> &::std::option::Option<f64> {
        &self.min_line_coverage_percentage
    }
    /// <p>The maximum line coverage percentage to report.</p>
    pub fn max_line_coverage_percentage(mut self, input: f64) -> Self {
        self.max_line_coverage_percentage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum line coverage percentage to report.</p>
    pub fn set_max_line_coverage_percentage(mut self, input: ::std::option::Option<f64>) -> Self {
        self.max_line_coverage_percentage = input;
        self
    }
    /// <p>The maximum line coverage percentage to report.</p>
    pub fn get_max_line_coverage_percentage(&self) -> &::std::option::Option<f64> {
        &self.max_line_coverage_percentage
    }
    /// Consumes the builder and constructs a [`DescribeCodeCoveragesInput`](crate::operation::describe_code_coverages::DescribeCodeCoveragesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_code_coverages::DescribeCodeCoveragesInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_code_coverages::DescribeCodeCoveragesInput {
            report_arn: self.report_arn,
            next_token: self.next_token,
            max_results: self.max_results,
            sort_order: self.sort_order,
            sort_by: self.sort_by,
            min_line_coverage_percentage: self.min_line_coverage_percentage,
            max_line_coverage_percentage: self.max_line_coverage_percentage,
        })
    }
}
