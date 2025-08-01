// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelQueryOutput {
    /// <p>A <code>CancellationMessage</code> is returned when a <code>CancelQuery</code> request for the query specified by <code>QueryId</code> has already been issued.</p>
    pub cancellation_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CancelQueryOutput {
    /// <p>A <code>CancellationMessage</code> is returned when a <code>CancelQuery</code> request for the query specified by <code>QueryId</code> has already been issued.</p>
    pub fn cancellation_message(&self) -> ::std::option::Option<&str> {
        self.cancellation_message.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CancelQueryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CancelQueryOutput {
    /// Creates a new builder-style object to manufacture [`CancelQueryOutput`](crate::operation::cancel_query::CancelQueryOutput).
    pub fn builder() -> crate::operation::cancel_query::builders::CancelQueryOutputBuilder {
        crate::operation::cancel_query::builders::CancelQueryOutputBuilder::default()
    }
}

/// A builder for [`CancelQueryOutput`](crate::operation::cancel_query::CancelQueryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelQueryOutputBuilder {
    pub(crate) cancellation_message: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CancelQueryOutputBuilder {
    /// <p>A <code>CancellationMessage</code> is returned when a <code>CancelQuery</code> request for the query specified by <code>QueryId</code> has already been issued.</p>
    pub fn cancellation_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cancellation_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A <code>CancellationMessage</code> is returned when a <code>CancelQuery</code> request for the query specified by <code>QueryId</code> has already been issued.</p>
    pub fn set_cancellation_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cancellation_message = input;
        self
    }
    /// <p>A <code>CancellationMessage</code> is returned when a <code>CancelQuery</code> request for the query specified by <code>QueryId</code> has already been issued.</p>
    pub fn get_cancellation_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.cancellation_message
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CancelQueryOutput`](crate::operation::cancel_query::CancelQueryOutput).
    pub fn build(self) -> crate::operation::cancel_query::CancelQueryOutput {
        crate::operation::cancel_query::CancelQueryOutput {
            cancellation_message: self.cancellation_message,
            _request_id: self._request_id,
        }
    }
}
