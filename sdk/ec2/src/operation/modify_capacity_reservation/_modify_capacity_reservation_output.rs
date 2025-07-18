// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyCapacityReservationOutput {
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub r#return: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ModifyCapacityReservationOutput {
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub fn r#return(&self) -> ::std::option::Option<bool> {
        self.r#return
    }
}
impl ::aws_types::request_id::RequestId for ModifyCapacityReservationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyCapacityReservationOutput {
    /// Creates a new builder-style object to manufacture [`ModifyCapacityReservationOutput`](crate::operation::modify_capacity_reservation::ModifyCapacityReservationOutput).
    pub fn builder() -> crate::operation::modify_capacity_reservation::builders::ModifyCapacityReservationOutputBuilder {
        crate::operation::modify_capacity_reservation::builders::ModifyCapacityReservationOutputBuilder::default()
    }
}

/// A builder for [`ModifyCapacityReservationOutput`](crate::operation::modify_capacity_reservation::ModifyCapacityReservationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyCapacityReservationOutputBuilder {
    pub(crate) r#return: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl ModifyCapacityReservationOutputBuilder {
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub fn r#return(mut self, input: bool) -> Self {
        self.r#return = ::std::option::Option::Some(input);
        self
    }
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub fn set_return(mut self, input: ::std::option::Option<bool>) -> Self {
        self.r#return = input;
        self
    }
    /// <p>Returns <code>true</code> if the request succeeds; otherwise, it returns an error.</p>
    pub fn get_return(&self) -> &::std::option::Option<bool> {
        &self.r#return
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyCapacityReservationOutput`](crate::operation::modify_capacity_reservation::ModifyCapacityReservationOutput).
    pub fn build(self) -> crate::operation::modify_capacity_reservation::ModifyCapacityReservationOutput {
        crate::operation::modify_capacity_reservation::ModifyCapacityReservationOutput {
            r#return: self.r#return,
            _request_id: self._request_id,
        }
    }
}
