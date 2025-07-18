// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMarketplaceModelEndpointsOutput {
    /// <p>An array of endpoint summaries.</p>
    pub marketplace_model_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::MarketplaceModelEndpointSummary>>,
    /// <p>The token for the next set of results. Use this token to get the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMarketplaceModelEndpointsOutput {
    /// <p>An array of endpoint summaries.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.marketplace_model_endpoints.is_none()`.
    pub fn marketplace_model_endpoints(&self) -> &[crate::types::MarketplaceModelEndpointSummary] {
        self.marketplace_model_endpoints.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of results. Use this token to get the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListMarketplaceModelEndpointsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListMarketplaceModelEndpointsOutput {
    /// Creates a new builder-style object to manufacture [`ListMarketplaceModelEndpointsOutput`](crate::operation::list_marketplace_model_endpoints::ListMarketplaceModelEndpointsOutput).
    pub fn builder() -> crate::operation::list_marketplace_model_endpoints::builders::ListMarketplaceModelEndpointsOutputBuilder {
        crate::operation::list_marketplace_model_endpoints::builders::ListMarketplaceModelEndpointsOutputBuilder::default()
    }
}

/// A builder for [`ListMarketplaceModelEndpointsOutput`](crate::operation::list_marketplace_model_endpoints::ListMarketplaceModelEndpointsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMarketplaceModelEndpointsOutputBuilder {
    pub(crate) marketplace_model_endpoints: ::std::option::Option<::std::vec::Vec<crate::types::MarketplaceModelEndpointSummary>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMarketplaceModelEndpointsOutputBuilder {
    /// Appends an item to `marketplace_model_endpoints`.
    ///
    /// To override the contents of this collection use [`set_marketplace_model_endpoints`](Self::set_marketplace_model_endpoints).
    ///
    /// <p>An array of endpoint summaries.</p>
    pub fn marketplace_model_endpoints(mut self, input: crate::types::MarketplaceModelEndpointSummary) -> Self {
        let mut v = self.marketplace_model_endpoints.unwrap_or_default();
        v.push(input);
        self.marketplace_model_endpoints = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of endpoint summaries.</p>
    pub fn set_marketplace_model_endpoints(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::MarketplaceModelEndpointSummary>>,
    ) -> Self {
        self.marketplace_model_endpoints = input;
        self
    }
    /// <p>An array of endpoint summaries.</p>
    pub fn get_marketplace_model_endpoints(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MarketplaceModelEndpointSummary>> {
        &self.marketplace_model_endpoints
    }
    /// <p>The token for the next set of results. Use this token to get the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Use this token to get the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Use this token to get the next set of results.</p>
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
    /// Consumes the builder and constructs a [`ListMarketplaceModelEndpointsOutput`](crate::operation::list_marketplace_model_endpoints::ListMarketplaceModelEndpointsOutput).
    pub fn build(self) -> crate::operation::list_marketplace_model_endpoints::ListMarketplaceModelEndpointsOutput {
        crate::operation::list_marketplace_model_endpoints::ListMarketplaceModelEndpointsOutput {
            marketplace_model_endpoints: self.marketplace_model_endpoints,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
