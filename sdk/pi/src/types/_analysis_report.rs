// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Retrieves the summary of the performance analysis report created for a time period.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AnalysisReport {
    /// <p>The name of the analysis report.</p>
    pub analysis_report_id: ::std::string::String,
    /// <p>The unique identifier of the analysis report.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>RDS</code></p></li>
    /// <li>
    /// <p><code>DOCDB</code></p></li>
    /// </ul>
    pub service_type: ::std::option::Option<crate::types::ServiceType>,
    /// <p>The time you created the analysis report.</p>
    pub create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The analysis start time in the report.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The analysis end time in the report.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The status of the created analysis report.</p>
    pub status: ::std::option::Option<crate::types::AnalysisStatus>,
    /// <p>The list of identified insights in the analysis report.</p>
    pub insights: ::std::option::Option<::std::vec::Vec<crate::types::Insight>>,
}
impl AnalysisReport {
    /// <p>The name of the analysis report.</p>
    pub fn analysis_report_id(&self) -> &str {
        use std::ops::Deref;
        self.analysis_report_id.deref()
    }
    /// <p>The unique identifier of the analysis report.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>RDS</code></p></li>
    /// <li>
    /// <p><code>DOCDB</code></p></li>
    /// </ul>
    pub fn service_type(&self) -> ::std::option::Option<&crate::types::ServiceType> {
        self.service_type.as_ref()
    }
    /// <p>The time you created the analysis report.</p>
    pub fn create_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.create_time.as_ref()
    }
    /// <p>The analysis start time in the report.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>The analysis end time in the report.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>The status of the created analysis report.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AnalysisStatus> {
        self.status.as_ref()
    }
    /// <p>The list of identified insights in the analysis report.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.insights.is_none()`.
    pub fn insights(&self) -> &[crate::types::Insight] {
        self.insights.as_deref().unwrap_or_default()
    }
}
impl AnalysisReport {
    /// Creates a new builder-style object to manufacture [`AnalysisReport`](crate::types::AnalysisReport).
    pub fn builder() -> crate::types::builders::AnalysisReportBuilder {
        crate::types::builders::AnalysisReportBuilder::default()
    }
}

/// A builder for [`AnalysisReport`](crate::types::AnalysisReport).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AnalysisReportBuilder {
    pub(crate) analysis_report_id: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) service_type: ::std::option::Option<crate::types::ServiceType>,
    pub(crate) create_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status: ::std::option::Option<crate::types::AnalysisStatus>,
    pub(crate) insights: ::std::option::Option<::std::vec::Vec<crate::types::Insight>>,
}
impl AnalysisReportBuilder {
    /// <p>The name of the analysis report.</p>
    /// This field is required.
    pub fn analysis_report_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.analysis_report_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the analysis report.</p>
    pub fn set_analysis_report_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.analysis_report_id = input;
        self
    }
    /// <p>The name of the analysis report.</p>
    pub fn get_analysis_report_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.analysis_report_id
    }
    /// <p>The unique identifier of the analysis report.</p>
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the analysis report.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>The unique identifier of the analysis report.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>RDS</code></p></li>
    /// <li>
    /// <p><code>DOCDB</code></p></li>
    /// </ul>
    pub fn service_type(mut self, input: crate::types::ServiceType) -> Self {
        self.service_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>RDS</code></p></li>
    /// <li>
    /// <p><code>DOCDB</code></p></li>
    /// </ul>
    pub fn set_service_type(mut self, input: ::std::option::Option<crate::types::ServiceType>) -> Self {
        self.service_type = input;
        self
    }
    /// <p>List the tags for the Amazon Web Services service for which Performance Insights returns metrics. Valid values are as follows:</p>
    /// <ul>
    /// <li>
    /// <p><code>RDS</code></p></li>
    /// <li>
    /// <p><code>DOCDB</code></p></li>
    /// </ul>
    pub fn get_service_type(&self) -> &::std::option::Option<crate::types::ServiceType> {
        &self.service_type
    }
    /// <p>The time you created the analysis report.</p>
    pub fn create_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.create_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time you created the analysis report.</p>
    pub fn set_create_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.create_time = input;
        self
    }
    /// <p>The time you created the analysis report.</p>
    pub fn get_create_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.create_time
    }
    /// <p>The analysis start time in the report.</p>
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The analysis start time in the report.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>The analysis start time in the report.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>The analysis end time in the report.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The analysis end time in the report.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>The analysis end time in the report.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>The status of the created analysis report.</p>
    pub fn status(mut self, input: crate::types::AnalysisStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the created analysis report.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AnalysisStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the created analysis report.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AnalysisStatus> {
        &self.status
    }
    /// Appends an item to `insights`.
    ///
    /// To override the contents of this collection use [`set_insights`](Self::set_insights).
    ///
    /// <p>The list of identified insights in the analysis report.</p>
    pub fn insights(mut self, input: crate::types::Insight) -> Self {
        let mut v = self.insights.unwrap_or_default();
        v.push(input);
        self.insights = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of identified insights in the analysis report.</p>
    pub fn set_insights(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Insight>>) -> Self {
        self.insights = input;
        self
    }
    /// <p>The list of identified insights in the analysis report.</p>
    pub fn get_insights(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Insight>> {
        &self.insights
    }
    /// Consumes the builder and constructs a [`AnalysisReport`](crate::types::AnalysisReport).
    /// This method will fail if any of the following fields are not set:
    /// - [`analysis_report_id`](crate::types::builders::AnalysisReportBuilder::analysis_report_id)
    pub fn build(self) -> ::std::result::Result<crate::types::AnalysisReport, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AnalysisReport {
            analysis_report_id: self.analysis_report_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "analysis_report_id",
                    "analysis_report_id was not specified but it is required when building AnalysisReport",
                )
            })?,
            identifier: self.identifier,
            service_type: self.service_type,
            create_time: self.create_time,
            start_time: self.start_time,
            end_time: self.end_time,
            status: self.status,
            insights: self.insights,
        })
    }
}
