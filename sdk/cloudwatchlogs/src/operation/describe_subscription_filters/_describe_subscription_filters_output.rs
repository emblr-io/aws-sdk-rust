// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSubscriptionFiltersOutput {
    /// <p>The subscription filters.</p>
    pub subscription_filters: ::std::option::Option<::std::vec::Vec<crate::types::SubscriptionFilter>>,
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeSubscriptionFiltersOutput {
    /// <p>The subscription filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.subscription_filters.is_none()`.
    pub fn subscription_filters(&self) -> &[crate::types::SubscriptionFilter] {
        self.subscription_filters.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeSubscriptionFiltersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeSubscriptionFiltersOutput {
    /// Creates a new builder-style object to manufacture [`DescribeSubscriptionFiltersOutput`](crate::operation::describe_subscription_filters::DescribeSubscriptionFiltersOutput).
    pub fn builder() -> crate::operation::describe_subscription_filters::builders::DescribeSubscriptionFiltersOutputBuilder {
        crate::operation::describe_subscription_filters::builders::DescribeSubscriptionFiltersOutputBuilder::default()
    }
}

/// A builder for [`DescribeSubscriptionFiltersOutput`](crate::operation::describe_subscription_filters::DescribeSubscriptionFiltersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSubscriptionFiltersOutputBuilder {
    pub(crate) subscription_filters: ::std::option::Option<::std::vec::Vec<crate::types::SubscriptionFilter>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeSubscriptionFiltersOutputBuilder {
    /// Appends an item to `subscription_filters`.
    ///
    /// To override the contents of this collection use [`set_subscription_filters`](Self::set_subscription_filters).
    ///
    /// <p>The subscription filters.</p>
    pub fn subscription_filters(mut self, input: crate::types::SubscriptionFilter) -> Self {
        let mut v = self.subscription_filters.unwrap_or_default();
        v.push(input);
        self.subscription_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The subscription filters.</p>
    pub fn set_subscription_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SubscriptionFilter>>) -> Self {
        self.subscription_filters = input;
        self
    }
    /// <p>The subscription filters.</p>
    pub fn get_subscription_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SubscriptionFilter>> {
        &self.subscription_filters
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
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
    /// Consumes the builder and constructs a [`DescribeSubscriptionFiltersOutput`](crate::operation::describe_subscription_filters::DescribeSubscriptionFiltersOutput).
    pub fn build(self) -> crate::operation::describe_subscription_filters::DescribeSubscriptionFiltersOutput {
        crate::operation::describe_subscription_filters::DescribeSubscriptionFiltersOutput {
            subscription_filters: self.subscription_filters,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
