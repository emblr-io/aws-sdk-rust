// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOrderOutput {
    /// <p>Information about an order.</p>
    pub order: ::std::option::Option<crate::types::Order>,
    _request_id: Option<String>,
}
impl GetOrderOutput {
    /// <p>Information about an order.</p>
    pub fn order(&self) -> ::std::option::Option<&crate::types::Order> {
        self.order.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetOrderOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetOrderOutput {
    /// Creates a new builder-style object to manufacture [`GetOrderOutput`](crate::operation::get_order::GetOrderOutput).
    pub fn builder() -> crate::operation::get_order::builders::GetOrderOutputBuilder {
        crate::operation::get_order::builders::GetOrderOutputBuilder::default()
    }
}

/// A builder for [`GetOrderOutput`](crate::operation::get_order::GetOrderOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOrderOutputBuilder {
    pub(crate) order: ::std::option::Option<crate::types::Order>,
    _request_id: Option<String>,
}
impl GetOrderOutputBuilder {
    /// <p>Information about an order.</p>
    pub fn order(mut self, input: crate::types::Order) -> Self {
        self.order = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about an order.</p>
    pub fn set_order(mut self, input: ::std::option::Option<crate::types::Order>) -> Self {
        self.order = input;
        self
    }
    /// <p>Information about an order.</p>
    pub fn get_order(&self) -> &::std::option::Option<crate::types::Order> {
        &self.order
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetOrderOutput`](crate::operation::get_order::GetOrderOutput).
    pub fn build(self) -> crate::operation::get_order::GetOrderOutput {
        crate::operation::get_order::GetOrderOutput {
            order: self.order,
            _request_id: self._request_id,
        }
    }
}
