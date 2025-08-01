// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The results of a Trusted Advisor check returned by <code>DescribeTrustedAdvisorCheckResult</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TrustedAdvisorCheckResult {
    /// <p>The unique identifier for the Trusted Advisor check.</p>
    pub check_id: ::std::string::String,
    /// <p>The time of the last refresh of the check.</p>
    pub timestamp: ::std::string::String,
    /// <p>The alert status of the check: "ok" (green), "warning" (yellow), "error" (red), or "not_available".</p>
    pub status: ::std::string::String,
    /// <p>Details about Amazon Web Services resources that were analyzed in a call to Trusted Advisor <code>DescribeTrustedAdvisorCheckSummaries</code>.</p>
    pub resources_summary: ::std::option::Option<crate::types::TrustedAdvisorResourcesSummary>,
    /// <p>Summary information that relates to the category of the check. Cost Optimizing is the only category that is currently supported.</p>
    pub category_specific_summary: ::std::option::Option<crate::types::TrustedAdvisorCategorySpecificSummary>,
    /// <p>The details about each resource listed in the check result.</p>
    pub flagged_resources: ::std::vec::Vec<crate::types::TrustedAdvisorResourceDetail>,
}
impl TrustedAdvisorCheckResult {
    /// <p>The unique identifier for the Trusted Advisor check.</p>
    pub fn check_id(&self) -> &str {
        use std::ops::Deref;
        self.check_id.deref()
    }
    /// <p>The time of the last refresh of the check.</p>
    pub fn timestamp(&self) -> &str {
        use std::ops::Deref;
        self.timestamp.deref()
    }
    /// <p>The alert status of the check: "ok" (green), "warning" (yellow), "error" (red), or "not_available".</p>
    pub fn status(&self) -> &str {
        use std::ops::Deref;
        self.status.deref()
    }
    /// <p>Details about Amazon Web Services resources that were analyzed in a call to Trusted Advisor <code>DescribeTrustedAdvisorCheckSummaries</code>.</p>
    pub fn resources_summary(&self) -> ::std::option::Option<&crate::types::TrustedAdvisorResourcesSummary> {
        self.resources_summary.as_ref()
    }
    /// <p>Summary information that relates to the category of the check. Cost Optimizing is the only category that is currently supported.</p>
    pub fn category_specific_summary(&self) -> ::std::option::Option<&crate::types::TrustedAdvisorCategorySpecificSummary> {
        self.category_specific_summary.as_ref()
    }
    /// <p>The details about each resource listed in the check result.</p>
    pub fn flagged_resources(&self) -> &[crate::types::TrustedAdvisorResourceDetail] {
        use std::ops::Deref;
        self.flagged_resources.deref()
    }
}
impl TrustedAdvisorCheckResult {
    /// Creates a new builder-style object to manufacture [`TrustedAdvisorCheckResult`](crate::types::TrustedAdvisorCheckResult).
    pub fn builder() -> crate::types::builders::TrustedAdvisorCheckResultBuilder {
        crate::types::builders::TrustedAdvisorCheckResultBuilder::default()
    }
}

/// A builder for [`TrustedAdvisorCheckResult`](crate::types::TrustedAdvisorCheckResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TrustedAdvisorCheckResultBuilder {
    pub(crate) check_id: ::std::option::Option<::std::string::String>,
    pub(crate) timestamp: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) resources_summary: ::std::option::Option<crate::types::TrustedAdvisorResourcesSummary>,
    pub(crate) category_specific_summary: ::std::option::Option<crate::types::TrustedAdvisorCategorySpecificSummary>,
    pub(crate) flagged_resources: ::std::option::Option<::std::vec::Vec<crate::types::TrustedAdvisorResourceDetail>>,
}
impl TrustedAdvisorCheckResultBuilder {
    /// <p>The unique identifier for the Trusted Advisor check.</p>
    /// This field is required.
    pub fn check_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.check_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the Trusted Advisor check.</p>
    pub fn set_check_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.check_id = input;
        self
    }
    /// <p>The unique identifier for the Trusted Advisor check.</p>
    pub fn get_check_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.check_id
    }
    /// <p>The time of the last refresh of the check.</p>
    /// This field is required.
    pub fn timestamp(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timestamp = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The time of the last refresh of the check.</p>
    pub fn set_timestamp(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timestamp = input;
        self
    }
    /// <p>The time of the last refresh of the check.</p>
    pub fn get_timestamp(&self) -> &::std::option::Option<::std::string::String> {
        &self.timestamp
    }
    /// <p>The alert status of the check: "ok" (green), "warning" (yellow), "error" (red), or "not_available".</p>
    /// This field is required.
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alert status of the check: "ok" (green), "warning" (yellow), "error" (red), or "not_available".</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The alert status of the check: "ok" (green), "warning" (yellow), "error" (red), or "not_available".</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>Details about Amazon Web Services resources that were analyzed in a call to Trusted Advisor <code>DescribeTrustedAdvisorCheckSummaries</code>.</p>
    /// This field is required.
    pub fn resources_summary(mut self, input: crate::types::TrustedAdvisorResourcesSummary) -> Self {
        self.resources_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about Amazon Web Services resources that were analyzed in a call to Trusted Advisor <code>DescribeTrustedAdvisorCheckSummaries</code>.</p>
    pub fn set_resources_summary(mut self, input: ::std::option::Option<crate::types::TrustedAdvisorResourcesSummary>) -> Self {
        self.resources_summary = input;
        self
    }
    /// <p>Details about Amazon Web Services resources that were analyzed in a call to Trusted Advisor <code>DescribeTrustedAdvisorCheckSummaries</code>.</p>
    pub fn get_resources_summary(&self) -> &::std::option::Option<crate::types::TrustedAdvisorResourcesSummary> {
        &self.resources_summary
    }
    /// <p>Summary information that relates to the category of the check. Cost Optimizing is the only category that is currently supported.</p>
    /// This field is required.
    pub fn category_specific_summary(mut self, input: crate::types::TrustedAdvisorCategorySpecificSummary) -> Self {
        self.category_specific_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Summary information that relates to the category of the check. Cost Optimizing is the only category that is currently supported.</p>
    pub fn set_category_specific_summary(mut self, input: ::std::option::Option<crate::types::TrustedAdvisorCategorySpecificSummary>) -> Self {
        self.category_specific_summary = input;
        self
    }
    /// <p>Summary information that relates to the category of the check. Cost Optimizing is the only category that is currently supported.</p>
    pub fn get_category_specific_summary(&self) -> &::std::option::Option<crate::types::TrustedAdvisorCategorySpecificSummary> {
        &self.category_specific_summary
    }
    /// Appends an item to `flagged_resources`.
    ///
    /// To override the contents of this collection use [`set_flagged_resources`](Self::set_flagged_resources).
    ///
    /// <p>The details about each resource listed in the check result.</p>
    pub fn flagged_resources(mut self, input: crate::types::TrustedAdvisorResourceDetail) -> Self {
        let mut v = self.flagged_resources.unwrap_or_default();
        v.push(input);
        self.flagged_resources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The details about each resource listed in the check result.</p>
    pub fn set_flagged_resources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TrustedAdvisorResourceDetail>>) -> Self {
        self.flagged_resources = input;
        self
    }
    /// <p>The details about each resource listed in the check result.</p>
    pub fn get_flagged_resources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TrustedAdvisorResourceDetail>> {
        &self.flagged_resources
    }
    /// Consumes the builder and constructs a [`TrustedAdvisorCheckResult`](crate::types::TrustedAdvisorCheckResult).
    /// This method will fail if any of the following fields are not set:
    /// - [`check_id`](crate::types::builders::TrustedAdvisorCheckResultBuilder::check_id)
    /// - [`timestamp`](crate::types::builders::TrustedAdvisorCheckResultBuilder::timestamp)
    /// - [`status`](crate::types::builders::TrustedAdvisorCheckResultBuilder::status)
    /// - [`flagged_resources`](crate::types::builders::TrustedAdvisorCheckResultBuilder::flagged_resources)
    pub fn build(self) -> ::std::result::Result<crate::types::TrustedAdvisorCheckResult, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TrustedAdvisorCheckResult {
            check_id: self.check_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "check_id",
                    "check_id was not specified but it is required when building TrustedAdvisorCheckResult",
                )
            })?,
            timestamp: self.timestamp.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "timestamp",
                    "timestamp was not specified but it is required when building TrustedAdvisorCheckResult",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building TrustedAdvisorCheckResult",
                )
            })?,
            resources_summary: self.resources_summary,
            category_specific_summary: self.category_specific_summary,
            flagged_resources: self.flagged_resources.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "flagged_resources",
                    "flagged_resources was not specified but it is required when building TrustedAdvisorCheckResult",
                )
            })?,
        })
    }
}
