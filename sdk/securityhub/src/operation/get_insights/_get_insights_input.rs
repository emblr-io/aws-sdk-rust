// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInsightsInput {
    /// <p>The ARNs of the insights to describe. If you don't provide any insight ARNs, then <code>GetInsights</code> returns all of your custom insights. It does not return any managed insights.</p>
    pub insight_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The token that is required for pagination. On your first call to the <code>GetInsights</code> operation, set the value of this parameter to <code>NULL</code>.</p>
    /// <p>For subsequent calls to the operation, to continue listing data, set the value of this parameter to the value returned from the previous response.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of items to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetInsightsInput {
    /// <p>The ARNs of the insights to describe. If you don't provide any insight ARNs, then <code>GetInsights</code> returns all of your custom insights. It does not return any managed insights.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.insight_arns.is_none()`.
    pub fn insight_arns(&self) -> &[::std::string::String] {
        self.insight_arns.as_deref().unwrap_or_default()
    }
    /// <p>The token that is required for pagination. On your first call to the <code>GetInsights</code> operation, set the value of this parameter to <code>NULL</code>.</p>
    /// <p>For subsequent calls to the operation, to continue listing data, set the value of this parameter to the value returned from the previous response.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of items to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetInsightsInput {
    /// Creates a new builder-style object to manufacture [`GetInsightsInput`](crate::operation::get_insights::GetInsightsInput).
    pub fn builder() -> crate::operation::get_insights::builders::GetInsightsInputBuilder {
        crate::operation::get_insights::builders::GetInsightsInputBuilder::default()
    }
}

/// A builder for [`GetInsightsInput`](crate::operation::get_insights::GetInsightsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInsightsInputBuilder {
    pub(crate) insight_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetInsightsInputBuilder {
    /// Appends an item to `insight_arns`.
    ///
    /// To override the contents of this collection use [`set_insight_arns`](Self::set_insight_arns).
    ///
    /// <p>The ARNs of the insights to describe. If you don't provide any insight ARNs, then <code>GetInsights</code> returns all of your custom insights. It does not return any managed insights.</p>
    pub fn insight_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.insight_arns.unwrap_or_default();
        v.push(input.into());
        self.insight_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARNs of the insights to describe. If you don't provide any insight ARNs, then <code>GetInsights</code> returns all of your custom insights. It does not return any managed insights.</p>
    pub fn set_insight_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.insight_arns = input;
        self
    }
    /// <p>The ARNs of the insights to describe. If you don't provide any insight ARNs, then <code>GetInsights</code> returns all of your custom insights. It does not return any managed insights.</p>
    pub fn get_insight_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.insight_arns
    }
    /// <p>The token that is required for pagination. On your first call to the <code>GetInsights</code> operation, set the value of this parameter to <code>NULL</code>.</p>
    /// <p>For subsequent calls to the operation, to continue listing data, set the value of this parameter to the value returned from the previous response.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that is required for pagination. On your first call to the <code>GetInsights</code> operation, set the value of this parameter to <code>NULL</code>.</p>
    /// <p>For subsequent calls to the operation, to continue listing data, set the value of this parameter to the value returned from the previous response.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that is required for pagination. On your first call to the <code>GetInsights</code> operation, set the value of this parameter to <code>NULL</code>.</p>
    /// <p>For subsequent calls to the operation, to continue listing data, set the value of this parameter to the value returned from the previous response.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of items to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of items to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of items to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetInsightsInput`](crate::operation::get_insights::GetInsightsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_insights::GetInsightsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_insights::GetInsightsInput {
            insight_arns: self.insight_arns,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
