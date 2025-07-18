// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListReservationsOutput {
    /// <p>The token that identifies the batch of results that you want to see.</p>
    /// <p>For example, you submit a <code>ListReservations</code> request with <code>MaxResults</code> set at 5. The service returns the first batch of results (up to 5) and a <code>NextToken</code> value. To see the next batch of results, you can submit the <code>ListReservations</code> request a second time and specify the <code>NextToken</code> value.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of all reservations that have been purchased by this account in the current Amazon Web Services Region.</p>
    pub reservations: ::std::option::Option<::std::vec::Vec<crate::types::Reservation>>,
    _request_id: Option<String>,
}
impl ListReservationsOutput {
    /// <p>The token that identifies the batch of results that you want to see.</p>
    /// <p>For example, you submit a <code>ListReservations</code> request with <code>MaxResults</code> set at 5. The service returns the first batch of results (up to 5) and a <code>NextToken</code> value. To see the next batch of results, you can submit the <code>ListReservations</code> request a second time and specify the <code>NextToken</code> value.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of all reservations that have been purchased by this account in the current Amazon Web Services Region.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reservations.is_none()`.
    pub fn reservations(&self) -> &[crate::types::Reservation] {
        self.reservations.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ListReservationsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListReservationsOutput {
    /// Creates a new builder-style object to manufacture [`ListReservationsOutput`](crate::operation::list_reservations::ListReservationsOutput).
    pub fn builder() -> crate::operation::list_reservations::builders::ListReservationsOutputBuilder {
        crate::operation::list_reservations::builders::ListReservationsOutputBuilder::default()
    }
}

/// A builder for [`ListReservationsOutput`](crate::operation::list_reservations::ListReservationsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListReservationsOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) reservations: ::std::option::Option<::std::vec::Vec<crate::types::Reservation>>,
    _request_id: Option<String>,
}
impl ListReservationsOutputBuilder {
    /// <p>The token that identifies the batch of results that you want to see.</p>
    /// <p>For example, you submit a <code>ListReservations</code> request with <code>MaxResults</code> set at 5. The service returns the first batch of results (up to 5) and a <code>NextToken</code> value. To see the next batch of results, you can submit the <code>ListReservations</code> request a second time and specify the <code>NextToken</code> value.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token that identifies the batch of results that you want to see.</p>
    /// <p>For example, you submit a <code>ListReservations</code> request with <code>MaxResults</code> set at 5. The service returns the first batch of results (up to 5) and a <code>NextToken</code> value. To see the next batch of results, you can submit the <code>ListReservations</code> request a second time and specify the <code>NextToken</code> value.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token that identifies the batch of results that you want to see.</p>
    /// <p>For example, you submit a <code>ListReservations</code> request with <code>MaxResults</code> set at 5. The service returns the first batch of results (up to 5) and a <code>NextToken</code> value. To see the next batch of results, you can submit the <code>ListReservations</code> request a second time and specify the <code>NextToken</code> value.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `reservations`.
    ///
    /// To override the contents of this collection use [`set_reservations`](Self::set_reservations).
    ///
    /// <p>A list of all reservations that have been purchased by this account in the current Amazon Web Services Region.</p>
    pub fn reservations(mut self, input: crate::types::Reservation) -> Self {
        let mut v = self.reservations.unwrap_or_default();
        v.push(input);
        self.reservations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of all reservations that have been purchased by this account in the current Amazon Web Services Region.</p>
    pub fn set_reservations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Reservation>>) -> Self {
        self.reservations = input;
        self
    }
    /// <p>A list of all reservations that have been purchased by this account in the current Amazon Web Services Region.</p>
    pub fn get_reservations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Reservation>> {
        &self.reservations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListReservationsOutput`](crate::operation::list_reservations::ListReservationsOutput).
    pub fn build(self) -> crate::operation::list_reservations::ListReservationsOutput {
        crate::operation::list_reservations::ListReservationsOutput {
            next_token: self.next_token,
            reservations: self.reservations,
            _request_id: self._request_id,
        }
    }
}
