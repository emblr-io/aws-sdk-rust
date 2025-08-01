// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPerformanceAnalysisReportInput {
    /// <p>The Amazon Web Services service for which Performance Insights will return metrics. Valid value is <code>RDS</code>.</p>
    pub service_type: ::std::option::Option<crate::types::ServiceType>,
    /// <p>An immutable identifier for a data source that is unique for an Amazon Web Services Region. Performance Insights gathers metrics from this data source. In the console, the identifier is shown as <i>ResourceID</i>. When you call <code>DescribeDBInstances</code>, the identifier is returned as <code>DbiResourceId</code>.</p>
    /// <p>To use a DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VW2X</code>.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>A unique identifier of the created analysis report. For example, <code>report-12345678901234567</code></p>
    pub analysis_report_id: ::std::option::Option<::std::string::String>,
    /// <p>Indicates the text format in the report. The options are <code>PLAIN_TEXT</code> or <code>MARKDOWN</code>. The default value is <code>plain text</code>.</p>
    pub text_format: ::std::option::Option<crate::types::TextFormat>,
    /// <p>The text language in the report. The default language is <code>EN_US</code> (English).</p>
    pub accept_language: ::std::option::Option<crate::types::AcceptLanguage>,
}
impl GetPerformanceAnalysisReportInput {
    /// <p>The Amazon Web Services service for which Performance Insights will return metrics. Valid value is <code>RDS</code>.</p>
    pub fn service_type(&self) -> ::std::option::Option<&crate::types::ServiceType> {
        self.service_type.as_ref()
    }
    /// <p>An immutable identifier for a data source that is unique for an Amazon Web Services Region. Performance Insights gathers metrics from this data source. In the console, the identifier is shown as <i>ResourceID</i>. When you call <code>DescribeDBInstances</code>, the identifier is returned as <code>DbiResourceId</code>.</p>
    /// <p>To use a DB instance as a data source, specify its <code>DbiResourceId</code> value. For example, specify <code>db-ABCDEFGHIJKLMNOPQRSTU1VW2X</code>.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>A unique identifier of the created analysis report. For example, <code>report-12345678901234567</code></p>
    pub fn analysis_report_id(&self) -> ::std::option::Option<&str> {
        self.analysis_report_id.as_deref()
    }
    /// <p>Indicates the text format in the report. The options are <code>PLAIN_TEXT</code> or <code>MARKDOWN</code>. The default value is <code>plain text</code>.</p>
    pub fn text_format(&self) -> ::std::option::Option<&crate::types::TextFormat> {
        self.text_format.as_ref()
    }
    /// <p>The text language in the report. The default language is <code>EN_US</code> (English).</p>
    pub fn accept_language(&self) -> ::std::option::Option<&crate::types::AcceptLanguage> {
        self.accept_language.as_ref()
    }
}
impl GetPerformanceAnalysisReportInput {
    /// Creates a new builder-style object to manufacture [`GetPerformanceAnalysisReportInput`](crate::operation::get_performance_analysis_report::GetPerformanceAnalysisReportInput).
    pub fn builder() -> crate::operation::get_performance_analysis_report::builders::GetPerformanceAnalysisReportInputBuilder {
        crate::operation::get_performance_analysis_report::builders::GetPerformanceAnalysisReportInputBuilder::default()
    }
}

/// A builder for [`GetPerformanceAnalysisReportInput`](crate::operation::get_performance_analysis_report::GetPerformanceAnalysisReportInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPerformanceAnalysisReportInputBuilder {
    pub(crate) service_type: ::std::option::Option<crate::types::ServiceType>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) analysis_report_id: ::std::option::Option<::std::string::String>,
    pub(crate) text_format: ::std::option::Option<crate::types::TextFormat>,
    pub(crate) accept_language: ::std::option::Option<crate::types::AcceptLanguage>,
}
impl GetPerformanceAnalysisReportInputBuilder {
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
    /// <p>A unique identifier of the created analysis report. For example, <code>report-12345678901234567</code></p>
    /// This field is required.
    pub fn analysis_report_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.analysis_report_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier of the created analysis report. For example, <code>report-12345678901234567</code></p>
    pub fn set_analysis_report_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.analysis_report_id = input;
        self
    }
    /// <p>A unique identifier of the created analysis report. For example, <code>report-12345678901234567</code></p>
    pub fn get_analysis_report_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.analysis_report_id
    }
    /// <p>Indicates the text format in the report. The options are <code>PLAIN_TEXT</code> or <code>MARKDOWN</code>. The default value is <code>plain text</code>.</p>
    pub fn text_format(mut self, input: crate::types::TextFormat) -> Self {
        self.text_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the text format in the report. The options are <code>PLAIN_TEXT</code> or <code>MARKDOWN</code>. The default value is <code>plain text</code>.</p>
    pub fn set_text_format(mut self, input: ::std::option::Option<crate::types::TextFormat>) -> Self {
        self.text_format = input;
        self
    }
    /// <p>Indicates the text format in the report. The options are <code>PLAIN_TEXT</code> or <code>MARKDOWN</code>. The default value is <code>plain text</code>.</p>
    pub fn get_text_format(&self) -> &::std::option::Option<crate::types::TextFormat> {
        &self.text_format
    }
    /// <p>The text language in the report. The default language is <code>EN_US</code> (English).</p>
    pub fn accept_language(mut self, input: crate::types::AcceptLanguage) -> Self {
        self.accept_language = ::std::option::Option::Some(input);
        self
    }
    /// <p>The text language in the report. The default language is <code>EN_US</code> (English).</p>
    pub fn set_accept_language(mut self, input: ::std::option::Option<crate::types::AcceptLanguage>) -> Self {
        self.accept_language = input;
        self
    }
    /// <p>The text language in the report. The default language is <code>EN_US</code> (English).</p>
    pub fn get_accept_language(&self) -> &::std::option::Option<crate::types::AcceptLanguage> {
        &self.accept_language
    }
    /// Consumes the builder and constructs a [`GetPerformanceAnalysisReportInput`](crate::operation::get_performance_analysis_report::GetPerformanceAnalysisReportInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_performance_analysis_report::GetPerformanceAnalysisReportInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_performance_analysis_report::GetPerformanceAnalysisReportInput {
            service_type: self.service_type,
            identifier: self.identifier,
            analysis_report_id: self.analysis_report_id,
            text_format: self.text_format,
            accept_language: self.accept_language,
        })
    }
}
