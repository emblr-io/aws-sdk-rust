// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCallAnalyticsCategoriesInput {
    /// <p>If your <code>ListCallAnalyticsCategories</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of Call Analytics categories to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListCallAnalyticsCategoriesInput {
    /// <p>If your <code>ListCallAnalyticsCategories</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of Call Analytics categories to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListCallAnalyticsCategoriesInput {
    /// Creates a new builder-style object to manufacture [`ListCallAnalyticsCategoriesInput`](crate::operation::list_call_analytics_categories::ListCallAnalyticsCategoriesInput).
    pub fn builder() -> crate::operation::list_call_analytics_categories::builders::ListCallAnalyticsCategoriesInputBuilder {
        crate::operation::list_call_analytics_categories::builders::ListCallAnalyticsCategoriesInputBuilder::default()
    }
}

/// A builder for [`ListCallAnalyticsCategoriesInput`](crate::operation::list_call_analytics_categories::ListCallAnalyticsCategoriesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCallAnalyticsCategoriesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListCallAnalyticsCategoriesInputBuilder {
    /// <p>If your <code>ListCallAnalyticsCategories</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If your <code>ListCallAnalyticsCategories</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If your <code>ListCallAnalyticsCategories</code> request returns more results than can be displayed, <code>NextToken</code> is displayed in the response with an associated string. To get the next page of results, copy this string and repeat your request, including <code>NextToken</code> with the value of the copied string. Repeat as needed to view all your results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of Call Analytics categories to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of Call Analytics categories to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of Call Analytics categories to return in each page of results. If there are fewer results than the value that you specify, only the actual results are returned. If you do not specify a value, a default of 5 is used.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListCallAnalyticsCategoriesInput`](crate::operation::list_call_analytics_categories::ListCallAnalyticsCategoriesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_call_analytics_categories::ListCallAnalyticsCategoriesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_call_analytics_categories::ListCallAnalyticsCategoriesInput {
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
