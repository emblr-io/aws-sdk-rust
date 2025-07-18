// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDeliveryOutput {
    /// <p>A structure that contains information about the delivery.</p>
    pub delivery: ::std::option::Option<crate::types::Delivery>,
    _request_id: Option<String>,
}
impl GetDeliveryOutput {
    /// <p>A structure that contains information about the delivery.</p>
    pub fn delivery(&self) -> ::std::option::Option<&crate::types::Delivery> {
        self.delivery.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDeliveryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDeliveryOutput {
    /// Creates a new builder-style object to manufacture [`GetDeliveryOutput`](crate::operation::get_delivery::GetDeliveryOutput).
    pub fn builder() -> crate::operation::get_delivery::builders::GetDeliveryOutputBuilder {
        crate::operation::get_delivery::builders::GetDeliveryOutputBuilder::default()
    }
}

/// A builder for [`GetDeliveryOutput`](crate::operation::get_delivery::GetDeliveryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDeliveryOutputBuilder {
    pub(crate) delivery: ::std::option::Option<crate::types::Delivery>,
    _request_id: Option<String>,
}
impl GetDeliveryOutputBuilder {
    /// <p>A structure that contains information about the delivery.</p>
    pub fn delivery(mut self, input: crate::types::Delivery) -> Self {
        self.delivery = ::std::option::Option::Some(input);
        self
    }
    /// <p>A structure that contains information about the delivery.</p>
    pub fn set_delivery(mut self, input: ::std::option::Option<crate::types::Delivery>) -> Self {
        self.delivery = input;
        self
    }
    /// <p>A structure that contains information about the delivery.</p>
    pub fn get_delivery(&self) -> &::std::option::Option<crate::types::Delivery> {
        &self.delivery
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDeliveryOutput`](crate::operation::get_delivery::GetDeliveryOutput).
    pub fn build(self) -> crate::operation::get_delivery::GetDeliveryOutput {
        crate::operation::get_delivery::GetDeliveryOutput {
            delivery: self.delivery,
            _request_id: self._request_id,
        }
    }
}
