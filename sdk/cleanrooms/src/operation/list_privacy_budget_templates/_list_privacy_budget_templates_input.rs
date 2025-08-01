// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPrivacyBudgetTemplatesInput {
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget templates are retrieved from the collaboration that this membership belongs to. Accepts a membership ID.</p>
    pub membership_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results that are returned for an API request call. The service chooses a default number if you don't set one. The service might return a `nextToken` even if the `maxResults` value has not been met.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListPrivacyBudgetTemplatesInput {
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget templates are retrieved from the collaboration that this membership belongs to. Accepts a membership ID.</p>
    pub fn membership_identifier(&self) -> ::std::option::Option<&str> {
        self.membership_identifier.as_deref()
    }
    /// <p>The pagination token that's used to fetch the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results that are returned for an API request call. The service chooses a default number if you don't set one. The service might return a `nextToken` even if the `maxResults` value has not been met.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListPrivacyBudgetTemplatesInput {
    /// Creates a new builder-style object to manufacture [`ListPrivacyBudgetTemplatesInput`](crate::operation::list_privacy_budget_templates::ListPrivacyBudgetTemplatesInput).
    pub fn builder() -> crate::operation::list_privacy_budget_templates::builders::ListPrivacyBudgetTemplatesInputBuilder {
        crate::operation::list_privacy_budget_templates::builders::ListPrivacyBudgetTemplatesInputBuilder::default()
    }
}

/// A builder for [`ListPrivacyBudgetTemplatesInput`](crate::operation::list_privacy_budget_templates::ListPrivacyBudgetTemplatesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPrivacyBudgetTemplatesInputBuilder {
    pub(crate) membership_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListPrivacyBudgetTemplatesInputBuilder {
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget templates are retrieved from the collaboration that this membership belongs to. Accepts a membership ID.</p>
    /// This field is required.
    pub fn membership_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.membership_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget templates are retrieved from the collaboration that this membership belongs to. Accepts a membership ID.</p>
    pub fn set_membership_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.membership_identifier = input;
        self
    }
    /// <p>A unique identifier for one of your memberships for a collaboration. The privacy budget templates are retrieved from the collaboration that this membership belongs to. Accepts a membership ID.</p>
    pub fn get_membership_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.membership_identifier
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
    /// <p>The maximum number of results that are returned for an API request call. The service chooses a default number if you don't set one. The service might return a `nextToken` even if the `maxResults` value has not been met.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that are returned for an API request call. The service chooses a default number if you don't set one. The service might return a `nextToken` even if the `maxResults` value has not been met.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that are returned for an API request call. The service chooses a default number if you don't set one. The service might return a `nextToken` even if the `maxResults` value has not been met.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListPrivacyBudgetTemplatesInput`](crate::operation::list_privacy_budget_templates::ListPrivacyBudgetTemplatesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_privacy_budget_templates::ListPrivacyBudgetTemplatesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_privacy_budget_templates::ListPrivacyBudgetTemplatesInput {
            membership_identifier: self.membership_identifier,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
