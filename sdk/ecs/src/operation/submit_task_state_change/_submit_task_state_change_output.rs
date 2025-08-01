// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SubmitTaskStateChangeOutput {
    /// <p>Acknowledgement of the state change.</p>
    pub acknowledgment: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SubmitTaskStateChangeOutput {
    /// <p>Acknowledgement of the state change.</p>
    pub fn acknowledgment(&self) -> ::std::option::Option<&str> {
        self.acknowledgment.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SubmitTaskStateChangeOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SubmitTaskStateChangeOutput {
    /// Creates a new builder-style object to manufacture [`SubmitTaskStateChangeOutput`](crate::operation::submit_task_state_change::SubmitTaskStateChangeOutput).
    pub fn builder() -> crate::operation::submit_task_state_change::builders::SubmitTaskStateChangeOutputBuilder {
        crate::operation::submit_task_state_change::builders::SubmitTaskStateChangeOutputBuilder::default()
    }
}

/// A builder for [`SubmitTaskStateChangeOutput`](crate::operation::submit_task_state_change::SubmitTaskStateChangeOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SubmitTaskStateChangeOutputBuilder {
    pub(crate) acknowledgment: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SubmitTaskStateChangeOutputBuilder {
    /// <p>Acknowledgement of the state change.</p>
    pub fn acknowledgment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.acknowledgment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Acknowledgement of the state change.</p>
    pub fn set_acknowledgment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.acknowledgment = input;
        self
    }
    /// <p>Acknowledgement of the state change.</p>
    pub fn get_acknowledgment(&self) -> &::std::option::Option<::std::string::String> {
        &self.acknowledgment
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SubmitTaskStateChangeOutput`](crate::operation::submit_task_state_change::SubmitTaskStateChangeOutput).
    pub fn build(self) -> crate::operation::submit_task_state_change::SubmitTaskStateChangeOutput {
        crate::operation::submit_task_state_change::SubmitTaskStateChangeOutput {
            acknowledgment: self.acknowledgment,
            _request_id: self._request_id,
        }
    }
}
