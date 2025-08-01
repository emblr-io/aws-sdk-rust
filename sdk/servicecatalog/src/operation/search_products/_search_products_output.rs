// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchProductsOutput {
    /// <p>Information about the product views.</p>
    pub product_view_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ProductViewSummary>>,
    /// <p>The product view aggregations.</p>
    pub product_view_aggregations:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ProductViewAggregationValue>>>,
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SearchProductsOutput {
    /// <p>Information about the product views.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.product_view_summaries.is_none()`.
    pub fn product_view_summaries(&self) -> &[crate::types::ProductViewSummary] {
        self.product_view_summaries.as_deref().unwrap_or_default()
    }
    /// <p>The product view aggregations.</p>
    pub fn product_view_aggregations(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ProductViewAggregationValue>>> {
        self.product_view_aggregations.as_ref()
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn next_page_token(&self) -> ::std::option::Option<&str> {
        self.next_page_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SearchProductsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SearchProductsOutput {
    /// Creates a new builder-style object to manufacture [`SearchProductsOutput`](crate::operation::search_products::SearchProductsOutput).
    pub fn builder() -> crate::operation::search_products::builders::SearchProductsOutputBuilder {
        crate::operation::search_products::builders::SearchProductsOutputBuilder::default()
    }
}

/// A builder for [`SearchProductsOutput`](crate::operation::search_products::SearchProductsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchProductsOutputBuilder {
    pub(crate) product_view_summaries: ::std::option::Option<::std::vec::Vec<crate::types::ProductViewSummary>>,
    pub(crate) product_view_aggregations:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ProductViewAggregationValue>>>,
    pub(crate) next_page_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SearchProductsOutputBuilder {
    /// Appends an item to `product_view_summaries`.
    ///
    /// To override the contents of this collection use [`set_product_view_summaries`](Self::set_product_view_summaries).
    ///
    /// <p>Information about the product views.</p>
    pub fn product_view_summaries(mut self, input: crate::types::ProductViewSummary) -> Self {
        let mut v = self.product_view_summaries.unwrap_or_default();
        v.push(input);
        self.product_view_summaries = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the product views.</p>
    pub fn set_product_view_summaries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ProductViewSummary>>) -> Self {
        self.product_view_summaries = input;
        self
    }
    /// <p>Information about the product views.</p>
    pub fn get_product_view_summaries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ProductViewSummary>> {
        &self.product_view_summaries
    }
    /// Adds a key-value pair to `product_view_aggregations`.
    ///
    /// To override the contents of this collection use [`set_product_view_aggregations`](Self::set_product_view_aggregations).
    ///
    /// <p>The product view aggregations.</p>
    pub fn product_view_aggregations(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: ::std::vec::Vec<crate::types::ProductViewAggregationValue>,
    ) -> Self {
        let mut hash_map = self.product_view_aggregations.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.product_view_aggregations = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The product view aggregations.</p>
    pub fn set_product_view_aggregations(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ProductViewAggregationValue>>>,
    ) -> Self {
        self.product_view_aggregations = input;
        self
    }
    /// <p>The product view aggregations.</p>
    pub fn get_product_view_aggregations(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ProductViewAggregationValue>>> {
        &self.product_view_aggregations
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn next_page_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_page_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn set_next_page_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_page_token = input;
        self
    }
    /// <p>The page token to use to retrieve the next set of results. If there are no additional results, this value is null.</p>
    pub fn get_next_page_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_page_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SearchProductsOutput`](crate::operation::search_products::SearchProductsOutput).
    pub fn build(self) -> crate::operation::search_products::SearchProductsOutput {
        crate::operation::search_products::SearchProductsOutput {
            product_view_summaries: self.product_view_summaries,
            product_view_aggregations: self.product_view_aggregations,
            next_page_token: self.next_page_token,
            _request_id: self._request_id,
        }
    }
}
