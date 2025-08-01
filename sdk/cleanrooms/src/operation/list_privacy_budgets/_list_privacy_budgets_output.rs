// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPrivacyBudgetsOutput {
    /// <p>An array that summarizes the privacy budgets. The summary includes collaboration information, membership information, privacy budget template information, and privacy budget details.</p>
    pub privacy_budget_summaries: ::std::vec::Vec<crate::types::PrivacyBudgetSummary>,
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPrivacyBudgetsOutput {
    /// <p>An array that summarizes the privacy budgets. The summary includes collaboration information, membership information, privacy budget template information, and privacy budget details.</p>
    pub fn privacy_budget_summaries(&self) -> &[crate::types::PrivacyBudgetSummary] {
        use std::ops::Deref;
        self.privacy_budget_summaries.deref()
    }
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListPrivacyBudgetsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListPrivacyBudgetsOutput {
    /// Creates a new builder-style object to manufacture [`ListPrivacyBudgetsOutput`](crate::operation::list_privacy_budgets::ListPrivacyBudgetsOutput).
    pub fn builder() -> crate::operation::list_privacy_budgets::builders::ListPrivacyBudgetsOutputBuilder {
        crate::operation::list_privacy_budgets::builders::ListPrivacyBudgetsOutputBuilder::default()
    }
}

/// A builder for [`ListPrivacyBudgetsOutput`](crate::operation::list_privacy_budgets::ListPrivacyBudgetsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPrivacyBudgetsOutputBuilder {
    pub(crate) privacy_budget_summaries: ::std::option::Option<::std::vec::Vec<crate::types::PrivacyBudgetSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListPrivacyBudgetsOutputBuilder {
    /// Appends an item to `privacy_budget_summaries`.
    ///
    /// To override the contents of this collection use [`set_privacy_budget_summaries`](Self::set_privacy_budget_summaries).
    ///
    /// <p>An array that summarizes the privacy budgets. The summary includes collaboration information, membership information, privacy budget template information, and privacy budget details.</p>
    pub fn privacy_budget_summaries(mut self, input: crate::types::PrivacyBudgetSummary) -> Self {
        let mut v = self.privacy_budget_summaries.unwrap_or_default();
        v.push(input);
        self.privacy_budget_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array that summarizes the privacy budgets. The summary includes collaboration information, membership information, privacy budget template information, and privacy budget details.</p>
    pub fn set_privacy_budget_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PrivacyBudgetSummary>>) -> Self {
        self.privacy_budget_summaries = input;
        self
    }
    /// <p>An array that summarizes the privacy budgets. The summary includes collaboration information, membership information, privacy budget template information, and privacy budget details.</p>
    pub fn get_privacy_budget_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PrivacyBudgetSummary>> {
        &self.privacy_budget_summaries
    }
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListPrivacyBudgetsOutput`](crate::operation::list_privacy_budgets::ListPrivacyBudgetsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`privacy_budget_summaries`](crate::operation::list_privacy_budgets::builders::ListPrivacyBudgetsOutputBuilder::privacy_budget_summaries)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_privacy_budgets::ListPrivacyBudgetsOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_privacy_budgets::ListPrivacyBudgetsOutput {
            privacy_budget_summaries: self.privacy_budget_summaries.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "privacy_budget_summaries",
                    "privacy_budget_summaries was not specified but it is required when building ListPrivacyBudgetsOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
