// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAssistantOutput {
    /// <p>Information about the assistant.</p>
    pub assistant: ::std::option::Option<crate::types::AssistantData>,
    _request_id: Option<String>,
}
impl GetAssistantOutput {
    /// <p>Information about the assistant.</p>
    pub fn assistant(&self) -> ::std::option::Option<&crate::types::AssistantData> {
        self.assistant.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetAssistantOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetAssistantOutput {
    /// Creates a new builder-style object to manufacture [`GetAssistantOutput`](crate::operation::get_assistant::GetAssistantOutput).
    pub fn builder() -> crate::operation::get_assistant::builders::GetAssistantOutputBuilder {
        crate::operation::get_assistant::builders::GetAssistantOutputBuilder::default()
    }
}

/// A builder for [`GetAssistantOutput`](crate::operation::get_assistant::GetAssistantOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAssistantOutputBuilder {
    pub(crate) assistant: ::std::option::Option<crate::types::AssistantData>,
    _request_id: Option<String>,
}
impl GetAssistantOutputBuilder {
    /// <p>Information about the assistant.</p>
    pub fn assistant(mut self, input: crate::types::AssistantData) -> Self {
        self.assistant = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the assistant.</p>
    pub fn set_assistant(mut self, input: ::std::option::Option<crate::types::AssistantData>) -> Self {
        self.assistant = input;
        self
    }
    /// <p>Information about the assistant.</p>
    pub fn get_assistant(&self) -> &::std::option::Option<crate::types::AssistantData> {
        &self.assistant
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetAssistantOutput`](crate::operation::get_assistant::GetAssistantOutput).
    pub fn build(self) -> crate::operation::get_assistant::GetAssistantOutput {
        crate::operation::get_assistant::GetAssistantOutput {
            assistant: self.assistant,
            _request_id: self._request_id,
        }
    }
}
