// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEventTypesOutput {
    /// <p>An array of event types.</p>
    pub event_types: ::std::option::Option<::std::vec::Vec<crate::types::EventType>>,
    /// <p>The next page token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetEventTypesOutput {
    /// <p>An array of event types.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.event_types.is_none()`.
    pub fn event_types(&self) -> &[crate::types::EventType] {
        self.event_types.as_deref().unwrap_or_default()
    }
    /// <p>The next page token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetEventTypesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetEventTypesOutput {
    /// Creates a new builder-style object to manufacture [`GetEventTypesOutput`](crate::operation::get_event_types::GetEventTypesOutput).
    pub fn builder() -> crate::operation::get_event_types::builders::GetEventTypesOutputBuilder {
        crate::operation::get_event_types::builders::GetEventTypesOutputBuilder::default()
    }
}

/// A builder for [`GetEventTypesOutput`](crate::operation::get_event_types::GetEventTypesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEventTypesOutputBuilder {
    pub(crate) event_types: ::std::option::Option<::std::vec::Vec<crate::types::EventType>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetEventTypesOutputBuilder {
    /// Appends an item to `event_types`.
    ///
    /// To override the contents of this collection use [`set_event_types`](Self::set_event_types).
    ///
    /// <p>An array of event types.</p>
    pub fn event_types(mut self, input: crate::types::EventType) -> Self {
        let mut v = self.event_types.unwrap_or_default();
        v.push(input);
        self.event_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of event types.</p>
    pub fn set_event_types(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EventType>>) -> Self {
        self.event_types = input;
        self
    }
    /// <p>An array of event types.</p>
    pub fn get_event_types(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EventType>> {
        &self.event_types
    }
    /// <p>The next page token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next page token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next page token.</p>
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
    /// Consumes the builder and constructs a [`GetEventTypesOutput`](crate::operation::get_event_types::GetEventTypesOutput).
    pub fn build(self) -> crate::operation::get_event_types::GetEventTypesOutput {
        crate::operation::get_event_types::GetEventTypesOutput {
            event_types: self.event_types,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
