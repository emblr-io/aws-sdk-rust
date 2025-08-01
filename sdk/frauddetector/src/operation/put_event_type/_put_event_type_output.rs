// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutEventTypeOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutEventTypeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutEventTypeOutput {
    /// Creates a new builder-style object to manufacture [`PutEventTypeOutput`](crate::operation::put_event_type::PutEventTypeOutput).
    pub fn builder() -> crate::operation::put_event_type::builders::PutEventTypeOutputBuilder {
        crate::operation::put_event_type::builders::PutEventTypeOutputBuilder::default()
    }
}

/// A builder for [`PutEventTypeOutput`](crate::operation::put_event_type::PutEventTypeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutEventTypeOutputBuilder {
    _request_id: Option<String>,
}
impl PutEventTypeOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutEventTypeOutput`](crate::operation::put_event_type::PutEventTypeOutput).
    pub fn build(self) -> crate::operation::put_event_type::PutEventTypeOutput {
        crate::operation::put_event_type::PutEventTypeOutput {
            _request_id: self._request_id,
        }
    }
}
