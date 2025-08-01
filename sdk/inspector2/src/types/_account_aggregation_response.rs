// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An aggregation of findings by Amazon Web Services account ID.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AccountAggregationResponse {
    /// <p>The Amazon Web Services account ID.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The number of findings by severity.</p>
    pub severity_counts: ::std::option::Option<crate::types::SeverityCounts>,
    /// <p>The number of findings that have an exploit available.</p>
    pub exploit_available_count: ::std::option::Option<i64>,
    /// <p>Details about the number of fixes.</p>
    pub fix_available_count: ::std::option::Option<i64>,
}
impl AccountAggregationResponse {
    /// <p>The Amazon Web Services account ID.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The number of findings by severity.</p>
    pub fn severity_counts(&self) -> ::std::option::Option<&crate::types::SeverityCounts> {
        self.severity_counts.as_ref()
    }
    /// <p>The number of findings that have an exploit available.</p>
    pub fn exploit_available_count(&self) -> ::std::option::Option<i64> {
        self.exploit_available_count
    }
    /// <p>Details about the number of fixes.</p>
    pub fn fix_available_count(&self) -> ::std::option::Option<i64> {
        self.fix_available_count
    }
}
impl AccountAggregationResponse {
    /// Creates a new builder-style object to manufacture [`AccountAggregationResponse`](crate::types::AccountAggregationResponse).
    pub fn builder() -> crate::types::builders::AccountAggregationResponseBuilder {
        crate::types::builders::AccountAggregationResponseBuilder::default()
    }
}

/// A builder for [`AccountAggregationResponse`](crate::types::AccountAggregationResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AccountAggregationResponseBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) severity_counts: ::std::option::Option<crate::types::SeverityCounts>,
    pub(crate) exploit_available_count: ::std::option::Option<i64>,
    pub(crate) fix_available_count: ::std::option::Option<i64>,
}
impl AccountAggregationResponseBuilder {
    /// <p>The Amazon Web Services account ID.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The number of findings by severity.</p>
    pub fn severity_counts(mut self, input: crate::types::SeverityCounts) -> Self {
        self.severity_counts = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of findings by severity.</p>
    pub fn set_severity_counts(mut self, input: ::std::option::Option<crate::types::SeverityCounts>) -> Self {
        self.severity_counts = input;
        self
    }
    /// <p>The number of findings by severity.</p>
    pub fn get_severity_counts(&self) -> &::std::option::Option<crate::types::SeverityCounts> {
        &self.severity_counts
    }
    /// <p>The number of findings that have an exploit available.</p>
    pub fn exploit_available_count(mut self, input: i64) -> Self {
        self.exploit_available_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of findings that have an exploit available.</p>
    pub fn set_exploit_available_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.exploit_available_count = input;
        self
    }
    /// <p>The number of findings that have an exploit available.</p>
    pub fn get_exploit_available_count(&self) -> &::std::option::Option<i64> {
        &self.exploit_available_count
    }
    /// <p>Details about the number of fixes.</p>
    pub fn fix_available_count(mut self, input: i64) -> Self {
        self.fix_available_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the number of fixes.</p>
    pub fn set_fix_available_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.fix_available_count = input;
        self
    }
    /// <p>Details about the number of fixes.</p>
    pub fn get_fix_available_count(&self) -> &::std::option::Option<i64> {
        &self.fix_available_count
    }
    /// Consumes the builder and constructs a [`AccountAggregationResponse`](crate::types::AccountAggregationResponse).
    pub fn build(self) -> crate::types::AccountAggregationResponse {
        crate::types::AccountAggregationResponse {
            account_id: self.account_id,
            severity_counts: self.severity_counts,
            exploit_available_count: self.exploit_available_count,
            fix_available_count: self.fix_available_count,
        }
    }
}
