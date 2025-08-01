// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The response to the request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAnalyzerOutput {
    /// <p>An <code>AnalyzerSummary</code> object that contains information about the analyzer.</p>
    pub analyzer: ::std::option::Option<crate::types::AnalyzerSummary>,
    _request_id: Option<String>,
}
impl GetAnalyzerOutput {
    /// <p>An <code>AnalyzerSummary</code> object that contains information about the analyzer.</p>
    pub fn analyzer(&self) -> ::std::option::Option<&crate::types::AnalyzerSummary> {
        self.analyzer.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetAnalyzerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAnalyzerOutput {
    /// Creates a new builder-style object to manufacture [`GetAnalyzerOutput`](crate::operation::get_analyzer::GetAnalyzerOutput).
    pub fn builder() -> crate::operation::get_analyzer::builders::GetAnalyzerOutputBuilder {
        crate::operation::get_analyzer::builders::GetAnalyzerOutputBuilder::default()
    }
}

/// A builder for [`GetAnalyzerOutput`](crate::operation::get_analyzer::GetAnalyzerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAnalyzerOutputBuilder {
    pub(crate) analyzer: ::std::option::Option<crate::types::AnalyzerSummary>,
    _request_id: Option<String>,
}
impl GetAnalyzerOutputBuilder {
    /// <p>An <code>AnalyzerSummary</code> object that contains information about the analyzer.</p>
    /// This field is required.
    pub fn analyzer(mut self, input: crate::types::AnalyzerSummary) -> Self {
        self.analyzer = ::std::option::Option::Some(input);
        self
    }
    /// <p>An <code>AnalyzerSummary</code> object that contains information about the analyzer.</p>
    pub fn set_analyzer(mut self, input: ::std::option::Option<crate::types::AnalyzerSummary>) -> Self {
        self.analyzer = input;
        self
    }
    /// <p>An <code>AnalyzerSummary</code> object that contains information about the analyzer.</p>
    pub fn get_analyzer(&self) -> &::std::option::Option<crate::types::AnalyzerSummary> {
        &self.analyzer
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAnalyzerOutput`](crate::operation::get_analyzer::GetAnalyzerOutput).
    pub fn build(self) -> crate::operation::get_analyzer::GetAnalyzerOutput {
        crate::operation::get_analyzer::GetAnalyzerOutput {
            analyzer: self.analyzer,
            _request_id: self._request_id,
        }
    }
}
