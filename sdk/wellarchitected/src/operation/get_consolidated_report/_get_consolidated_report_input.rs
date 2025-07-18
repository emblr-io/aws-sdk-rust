// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConsolidatedReportInput {
    /// <p>The format of the consolidated report.</p>
    /// <p>For <code>PDF</code>, <code>Base64String</code> is returned. For <code>JSON</code>, <code>Metrics</code> is returned.</p>
    pub format: ::std::option::Option<crate::types::ReportFormat>,
    /// <p>Set to <code>true</code> to have shared resources included in the report.</p>
    pub include_shared_resources: ::std::option::Option<bool>,
    /// <p>The token to use to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return for this request.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetConsolidatedReportInput {
    /// <p>The format of the consolidated report.</p>
    /// <p>For <code>PDF</code>, <code>Base64String</code> is returned. For <code>JSON</code>, <code>Metrics</code> is returned.</p>
    pub fn format(&self) -> ::std::option::Option<&crate::types::ReportFormat> {
        self.format.as_ref()
    }
    /// <p>Set to <code>true</code> to have shared resources included in the report.</p>
    pub fn include_shared_resources(&self) -> ::std::option::Option<bool> {
        self.include_shared_resources
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetConsolidatedReportInput {
    /// Creates a new builder-style object to manufacture [`GetConsolidatedReportInput`](crate::operation::get_consolidated_report::GetConsolidatedReportInput).
    pub fn builder() -> crate::operation::get_consolidated_report::builders::GetConsolidatedReportInputBuilder {
        crate::operation::get_consolidated_report::builders::GetConsolidatedReportInputBuilder::default()
    }
}

/// A builder for [`GetConsolidatedReportInput`](crate::operation::get_consolidated_report::GetConsolidatedReportInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConsolidatedReportInputBuilder {
    pub(crate) format: ::std::option::Option<crate::types::ReportFormat>,
    pub(crate) include_shared_resources: ::std::option::Option<bool>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetConsolidatedReportInputBuilder {
    /// <p>The format of the consolidated report.</p>
    /// <p>For <code>PDF</code>, <code>Base64String</code> is returned. For <code>JSON</code>, <code>Metrics</code> is returned.</p>
    /// This field is required.
    pub fn format(mut self, input: crate::types::ReportFormat) -> Self {
        self.format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format of the consolidated report.</p>
    /// <p>For <code>PDF</code>, <code>Base64String</code> is returned. For <code>JSON</code>, <code>Metrics</code> is returned.</p>
    pub fn set_format(mut self, input: ::std::option::Option<crate::types::ReportFormat>) -> Self {
        self.format = input;
        self
    }
    /// <p>The format of the consolidated report.</p>
    /// <p>For <code>PDF</code>, <code>Base64String</code> is returned. For <code>JSON</code>, <code>Metrics</code> is returned.</p>
    pub fn get_format(&self) -> &::std::option::Option<crate::types::ReportFormat> {
        &self.format
    }
    /// <p>Set to <code>true</code> to have shared resources included in the report.</p>
    pub fn include_shared_resources(mut self, input: bool) -> Self {
        self.include_shared_resources = ::std::option::Option::Some(input);
        self
    }
    /// <p>Set to <code>true</code> to have shared resources included in the report.</p>
    pub fn set_include_shared_resources(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_shared_resources = input;
        self
    }
    /// <p>Set to <code>true</code> to have shared resources included in the report.</p>
    pub fn get_include_shared_resources(&self) -> &::std::option::Option<bool> {
        &self.include_shared_resources
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return for this request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetConsolidatedReportInput`](crate::operation::get_consolidated_report::GetConsolidatedReportInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_consolidated_report::GetConsolidatedReportInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_consolidated_report::GetConsolidatedReportInput {
            format: self.format,
            include_shared_resources: self.include_shared_resources,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
