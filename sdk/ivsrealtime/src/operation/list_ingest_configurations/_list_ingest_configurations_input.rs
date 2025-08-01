// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListIngestConfigurationsInput {
    /// <p>Filters the response list to match the specified stage ARN. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub filter_by_stage_arn: ::std::option::Option<::std::string::String>,
    /// <p>Filters the response list to match the specified state. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub filter_by_state: ::std::option::Option<crate::types::IngestConfigurationState>,
    /// <p>The first IngestConfiguration to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListIngestConfigurationsInput {
    /// <p>Filters the response list to match the specified stage ARN. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub fn filter_by_stage_arn(&self) -> ::std::option::Option<&str> {
        self.filter_by_stage_arn.as_deref()
    }
    /// <p>Filters the response list to match the specified state. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub fn filter_by_state(&self) -> ::std::option::Option<&crate::types::IngestConfigurationState> {
        self.filter_by_state.as_ref()
    }
    /// <p>The first IngestConfiguration to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListIngestConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`ListIngestConfigurationsInput`](crate::operation::list_ingest_configurations::ListIngestConfigurationsInput).
    pub fn builder() -> crate::operation::list_ingest_configurations::builders::ListIngestConfigurationsInputBuilder {
        crate::operation::list_ingest_configurations::builders::ListIngestConfigurationsInputBuilder::default()
    }
}

/// A builder for [`ListIngestConfigurationsInput`](crate::operation::list_ingest_configurations::ListIngestConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListIngestConfigurationsInputBuilder {
    pub(crate) filter_by_stage_arn: ::std::option::Option<::std::string::String>,
    pub(crate) filter_by_state: ::std::option::Option<crate::types::IngestConfigurationState>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListIngestConfigurationsInputBuilder {
    /// <p>Filters the response list to match the specified stage ARN. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub fn filter_by_stage_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.filter_by_stage_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Filters the response list to match the specified stage ARN. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub fn set_filter_by_stage_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.filter_by_stage_arn = input;
        self
    }
    /// <p>Filters the response list to match the specified stage ARN. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub fn get_filter_by_stage_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.filter_by_stage_arn
    }
    /// <p>Filters the response list to match the specified state. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub fn filter_by_state(mut self, input: crate::types::IngestConfigurationState) -> Self {
        self.filter_by_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>Filters the response list to match the specified state. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub fn set_filter_by_state(mut self, input: ::std::option::Option<crate::types::IngestConfigurationState>) -> Self {
        self.filter_by_state = input;
        self
    }
    /// <p>Filters the response list to match the specified state. Only one filter (by stage ARN or by state) can be used at a time.</p>
    pub fn get_filter_by_state(&self) -> &::std::option::Option<crate::types::IngestConfigurationState> {
        &self.filter_by_state
    }
    /// <p>The first IngestConfiguration to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The first IngestConfiguration to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The first IngestConfiguration to retrieve. This is used for pagination; see the <code>nextToken</code> response field.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Maximum number of results to return. Default: 50.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListIngestConfigurationsInput`](crate::operation::list_ingest_configurations::ListIngestConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_ingest_configurations::ListIngestConfigurationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_ingest_configurations::ListIngestConfigurationsInput {
            filter_by_stage_arn: self.filter_by_stage_arn,
            filter_by_state: self.filter_by_state,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
