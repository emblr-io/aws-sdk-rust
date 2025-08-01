// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetActionOutput {
    /// <p>Information about the action.</p>
    pub action: ::std::option::Option<crate::types::Action>,
    _request_id: Option<String>,
}
impl GetActionOutput {
    /// <p>Information about the action.</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::Action> {
        self.action.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetActionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetActionOutput {
    /// Creates a new builder-style object to manufacture [`GetActionOutput`](crate::operation::get_action::GetActionOutput).
    pub fn builder() -> crate::operation::get_action::builders::GetActionOutputBuilder {
        crate::operation::get_action::builders::GetActionOutputBuilder::default()
    }
}

/// A builder for [`GetActionOutput`](crate::operation::get_action::GetActionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetActionOutputBuilder {
    pub(crate) action: ::std::option::Option<crate::types::Action>,
    _request_id: Option<String>,
}
impl GetActionOutputBuilder {
    /// <p>Information about the action.</p>
    pub fn action(mut self, input: crate::types::Action) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the action.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::Action>) -> Self {
        self.action = input;
        self
    }
    /// <p>Information about the action.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::Action> {
        &self.action
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetActionOutput`](crate::operation::get_action::GetActionOutput).
    pub fn build(self) -> crate::operation::get_action::GetActionOutput {
        crate::operation::get_action::GetActionOutput {
            action: self.action,
            _request_id: self._request_id,
        }
    }
}
