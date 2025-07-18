// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartTriggerOutput {
    /// <p>The name of the trigger that was started.</p>
    pub name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartTriggerOutput {
    /// <p>The name of the trigger that was started.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for StartTriggerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartTriggerOutput {
    /// Creates a new builder-style object to manufacture [`StartTriggerOutput`](crate::operation::start_trigger::StartTriggerOutput).
    pub fn builder() -> crate::operation::start_trigger::builders::StartTriggerOutputBuilder {
        crate::operation::start_trigger::builders::StartTriggerOutputBuilder::default()
    }
}

/// A builder for [`StartTriggerOutput`](crate::operation::start_trigger::StartTriggerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartTriggerOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartTriggerOutputBuilder {
    /// <p>The name of the trigger that was started.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the trigger that was started.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the trigger that was started.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartTriggerOutput`](crate::operation::start_trigger::StartTriggerOutput).
    pub fn build(self) -> crate::operation::start_trigger::StartTriggerOutput {
        crate::operation::start_trigger::StartTriggerOutput {
            name: self.name,
            _request_id: self._request_id,
        }
    }
}
