// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeletePerformanceAnalysisReportInput {
    /// <p>The Amazon Web Services service for which Performance Insights will return metrics. Valid value is <code>RDS</code>.</p>
    pub service_type: ::std::option::Option<crate::types::ServiceType>,
    /// <p>An immutable identifier for a data source that is unique for an Amazon Web Services Region. Performance Insights gathers metrics from this data source. In the console, the identifier is shown as <i>ResourceID</i>. When you call <code>DescribeDBInstances</code>, the identifier is returned as <code>DbiResourceId</code>.</p>
    /// <p>To use a DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VW2X</code>.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the analysis report for deletion.</p>
    pub analysis_report_id: ::std::option::Option<::std::string::String>,
}
impl DeletePerformanceAnalysisReportInput {
    /// <p>The Amazon Web Services service for which Performance Insights will return metrics. Valid value is <code>RDS</code>.</p>
    pub fn service_type(&self) -> ::std::option::Option<&crate::types::ServiceType> {
        self.service_type.as_ref()
    }
    /// <p>An immutable identifier for a data source that is unique for an Amazon Web Services Region. Performance Insights gathers metrics from this data source. In the console, the identifier is shown as <i>ResourceID</i>. When you call <code>DescribeDBInstances</code>, the identifier is returned as <code>DbiResourceId</code>.</p>
    /// <p>To use a DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VW2X</code>.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>The unique identifier of the analysis report for deletion.</p>
    pub fn analysis_report_id(&self) -> ::std::option::Option<&str> {
        self.analysis_report_id.as_deref()
    }
}
impl DeletePerformanceAnalysisReportInput {
    /// Creates a new builder-style object to manufacture [`DeletePerformanceAnalysisReportInput`](crate::operation::delete_performance_analysis_report::DeletePerformanceAnalysisReportInput).
    pub fn builder() -> crate::operation::delete_performance_analysis_report::builders::DeletePerformanceAnalysisReportInputBuilder {
        crate::operation::delete_performance_analysis_report::builders::DeletePerformanceAnalysisReportInputBuilder::default()
    }
}

/// A builder for [`DeletePerformanceAnalysisReportInput`](crate::operation::delete_performance_analysis_report::DeletePerformanceAnalysisReportInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeletePerformanceAnalysisReportInputBuilder {
    pub(crate) service_type: ::std::option::Option<crate::types::ServiceType>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) analysis_report_id: ::std::option::Option<::std::string::String>,
}
impl DeletePerformanceAnalysisReportInputBuilder {
    /// <p>The Amazon Web Services service for which Performance Insights will return metrics. Valid value is <code>RDS</code>.</p>
    /// This field is required.
    pub fn service_type(mut self, input: crate::types::ServiceType) -> Self {
        self.service_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Web Services service for which Performance Insights will return metrics. Valid value is <code>RDS</code>.</p>
    pub fn set_service_type(mut self, input: ::std::option::Option<crate::types::ServiceType>) -> Self {
        self.service_type = input;
        self
    }
    /// <p>The Amazon Web Services service for which Performance Insights will return metrics. Valid value is <code>RDS</code>.</p>
    pub fn get_service_type(&self) -> &::std::option::Option<crate::types::ServiceType> {
        &self.service_type
    }
    /// <p>An immutable identifier for a data source that is unique for an Amazon Web Services Region. Performance Insights gathers metrics from this data source. In the console, the identifier is shown as <i>ResourceID</i>. When you call <code>DescribeDBInstances</code>, the identifier is returned as <code>DbiResourceId</code>.</p>
    /// <p>To use a DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VW2X</code>.</p>
    /// This field is required.
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An immutable identifier for a data source that is unique for an Amazon Web Services Region. Performance Insights gathers metrics from this data source. In the console, the identifier is shown as <i>ResourceID</i>. When you call <code>DescribeDBInstances</code>, the identifier is returned as <code>DbiResourceId</code>.</p>
    /// <p>To use a DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VW2X</code>.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>An immutable identifier for a data source that is unique for an Amazon Web Services Region. Performance Insights gathers metrics from this data source. In the console, the identifier is shown as <i>ResourceID</i>. When you call <code>DescribeDBInstances</code>, the identifier is returned as <code>DbiResourceId</code>.</p>
    /// <p>To use a DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VW2X</code>.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>The unique identifier of the analysis report for deletion.</p>
    /// This field is required.
    pub fn analysis_report_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.analysis_report_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the analysis report for deletion.</p>
    pub fn set_analysis_report_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.analysis_report_id = input;
        self
    }
    /// <p>The unique identifier of the analysis report for deletion.</p>
    pub fn get_analysis_report_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.analysis_report_id
    }
    /// Consumes the builder and constructs a [`DeletePerformanceAnalysisReportInput`](crate::operation::delete_performance_analysis_report::DeletePerformanceAnalysisReportInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_performance_analysis_report::DeletePerformanceAnalysisReportInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_performance_analysis_report::DeletePerformanceAnalysisReportInput {
                service_type: self.service_type,
                identifier: self.identifier,
                analysis_report_id: self.analysis_report_id,
            },
        )
    }
}
