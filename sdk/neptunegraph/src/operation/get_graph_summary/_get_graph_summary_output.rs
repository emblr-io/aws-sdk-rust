// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetGraphSummaryOutput {
    /// <p>Display the version of this tool.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The timestamp, in ISO 8601 format, of the time at which Neptune Analytics last computed statistics.</p>
    pub last_statistics_computation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The graph summary.</p>
    pub graph_summary: ::std::option::Option<crate::types::GraphDataSummary>,
    _request_id: Option<String>,
}
impl GetGraphSummaryOutput {
    /// <p>Display the version of this tool.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The timestamp, in ISO 8601 format, of the time at which Neptune Analytics last computed statistics.</p>
    pub fn last_statistics_computation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_statistics_computation_time.as_ref()
    }
    /// <p>The graph summary.</p>
    pub fn graph_summary(&self) -> ::std::option::Option<&crate::types::GraphDataSummary> {
        self.graph_summary.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetGraphSummaryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetGraphSummaryOutput {
    /// Creates a new builder-style object to manufacture [`GetGraphSummaryOutput`](crate::operation::get_graph_summary::GetGraphSummaryOutput).
    pub fn builder() -> crate::operation::get_graph_summary::builders::GetGraphSummaryOutputBuilder {
        crate::operation::get_graph_summary::builders::GetGraphSummaryOutputBuilder::default()
    }
}

/// A builder for [`GetGraphSummaryOutput`](crate::operation::get_graph_summary::GetGraphSummaryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetGraphSummaryOutputBuilder {
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) last_statistics_computation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) graph_summary: ::std::option::Option<crate::types::GraphDataSummary>,
    _request_id: Option<String>,
}
impl GetGraphSummaryOutputBuilder {
    /// <p>Display the version of this tool.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Display the version of this tool.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>Display the version of this tool.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The timestamp, in ISO 8601 format, of the time at which Neptune Analytics last computed statistics.</p>
    pub fn last_statistics_computation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_statistics_computation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The timestamp, in ISO 8601 format, of the time at which Neptune Analytics last computed statistics.</p>
    pub fn set_last_statistics_computation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_statistics_computation_time = input;
        self
    }
    /// <p>The timestamp, in ISO 8601 format, of the time at which Neptune Analytics last computed statistics.</p>
    pub fn get_last_statistics_computation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_statistics_computation_time
    }
    /// <p>The graph summary.</p>
    pub fn graph_summary(mut self, input: crate::types::GraphDataSummary) -> Self {
        self.graph_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>The graph summary.</p>
    pub fn set_graph_summary(mut self, input: ::std::option::Option<crate::types::GraphDataSummary>) -> Self {
        self.graph_summary = input;
        self
    }
    /// <p>The graph summary.</p>
    pub fn get_graph_summary(&self) -> &::std::option::Option<crate::types::GraphDataSummary> {
        &self.graph_summary
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetGraphSummaryOutput`](crate::operation::get_graph_summary::GetGraphSummaryOutput).
    pub fn build(self) -> crate::operation::get_graph_summary::GetGraphSummaryOutput {
        crate::operation::get_graph_summary::GetGraphSummaryOutput {
            version: self.version,
            last_statistics_computation_time: self.last_statistics_computation_time,
            graph_summary: self.graph_summary,
            _request_id: self._request_id,
        }
    }
}
