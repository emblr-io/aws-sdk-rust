// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDeliverySourcesOutput {
    /// <p>An array of structures. Each structure contains information about one delivery source in the account.</p>
    pub delivery_sources: ::std::option::Option<::std::vec::Vec<crate::types::DeliverySource>>,
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeDeliverySourcesOutput {
    /// <p>An array of structures. Each structure contains information about one delivery source in the account.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.delivery_sources.is_none()`.
    pub fn delivery_sources(&self) -> &[crate::types::DeliverySource] {
        self.delivery_sources.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next set of items to return. The token expires after 24 hours.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDeliverySourcesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDeliverySourcesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDeliverySourcesOutput`](crate::operation::describe_delivery_sources::DescribeDeliverySourcesOutput).
    pub fn builder() -> crate::operation::describe_delivery_sources::builders::DescribeDeliverySourcesOutputBuilder {
        crate::operation::describe_delivery_sources::builders::DescribeDeliverySourcesOutputBuilder::default()
    }
}

/// A builder for [`DescribeDeliverySourcesOutput`](crate::operation::describe_delivery_sources::DescribeDeliverySourcesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDeliverySourcesOutputBuilder {
    pub(crate) delivery_sources: ::std::option::Option<::std::vec::Vec<crate::types::DeliverySource>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeDeliverySourcesOutputBuilder {
    /// Appends an item to `delivery_sources`.
    ///
    /// To override the contents of this collection use [`set_delivery_sources`](Self::set_delivery_sources).
    ///
    /// <p>An array of structures. Each structure contains information about one delivery source in the account.</p>
    pub fn delivery_sources(mut self, input: crate::types::DeliverySource) -> Self {
        let mut v = self.delivery_sources.unwrap_or_default();
        v.push(input);
        self.delivery_sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of structures. Each structure contains information about one delivery source in the account.</p>
    pub fn set_delivery_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DeliverySource>>) -> Self {
        self.delivery_sources = input;
        self
    }
    /// <p>An array of structures. Each structure contains information about one delivery source in the account.</p>
    pub fn get_delivery_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DeliverySource>> {
        &self.delivery_sources
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
    /// Consumes the builder and constructs a [`DescribeDeliverySourcesOutput`](crate::operation::describe_delivery_sources::DescribeDeliverySourcesOutput).
    pub fn build(self) -> crate::operation::describe_delivery_sources::DescribeDeliverySourcesOutput {
        crate::operation::describe_delivery_sources::DescribeDeliverySourcesOutput {
            delivery_sources: self.delivery_sources,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
