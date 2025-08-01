// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCostCategoryDefinitionsInput {
    /// <p>The date when the Cost Category was effective.</p>
    pub effective_on: ::std::option::Option<::std::string::String>,
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The number of entries a paginated response contains.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListCostCategoryDefinitionsInput {
    /// <p>The date when the Cost Category was effective.</p>
    pub fn effective_on(&self) -> ::std::option::Option<&str> {
        self.effective_on.as_deref()
    }
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The number of entries a paginated response contains.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListCostCategoryDefinitionsInput {
    /// Creates a new builder-style object to manufacture [`ListCostCategoryDefinitionsInput`](crate::operation::list_cost_category_definitions::ListCostCategoryDefinitionsInput).
    pub fn builder() -> crate::operation::list_cost_category_definitions::builders::ListCostCategoryDefinitionsInputBuilder {
        crate::operation::list_cost_category_definitions::builders::ListCostCategoryDefinitionsInputBuilder::default()
    }
}

/// A builder for [`ListCostCategoryDefinitionsInput`](crate::operation::list_cost_category_definitions::ListCostCategoryDefinitionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCostCategoryDefinitionsInputBuilder {
    pub(crate) effective_on: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListCostCategoryDefinitionsInputBuilder {
    /// <p>The date when the Cost Category was effective.</p>
    pub fn effective_on(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.effective_on = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date when the Cost Category was effective.</p>
    pub fn set_effective_on(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.effective_on = input;
        self
    }
    /// <p>The date when the Cost Category was effective.</p>
    pub fn get_effective_on(&self) -> &::std::option::Option<::std::string::String> {
        &self.effective_on
    }
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to retrieve the next set of results. Amazon Web Services provides the token when the response from a previous call has more results than the maximum page size.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The number of entries a paginated response contains.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of entries a paginated response contains.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The number of entries a paginated response contains.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListCostCategoryDefinitionsInput`](crate::operation::list_cost_category_definitions::ListCostCategoryDefinitionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_cost_category_definitions::ListCostCategoryDefinitionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_cost_category_definitions::ListCostCategoryDefinitionsInput {
            effective_on: self.effective_on,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
