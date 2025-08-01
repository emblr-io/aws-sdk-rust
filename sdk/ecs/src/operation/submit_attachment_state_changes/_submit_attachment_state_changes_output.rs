// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SubmitAttachmentStateChangesOutput {
    /// <p>Acknowledgement of the state change.</p>
    pub acknowledgment: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SubmitAttachmentStateChangesOutput {
    /// <p>Acknowledgement of the state change.</p>
    pub fn acknowledgment(&self) -> ::std::option::Option<&str> {
        self.acknowledgment.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for SubmitAttachmentStateChangesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SubmitAttachmentStateChangesOutput {
    /// Creates a new builder-style object to manufacture [`SubmitAttachmentStateChangesOutput`](crate::operation::submit_attachment_state_changes::SubmitAttachmentStateChangesOutput).
    pub fn builder() -> crate::operation::submit_attachment_state_changes::builders::SubmitAttachmentStateChangesOutputBuilder {
        crate::operation::submit_attachment_state_changes::builders::SubmitAttachmentStateChangesOutputBuilder::default()
    }
}

/// A builder for [`SubmitAttachmentStateChangesOutput`](crate::operation::submit_attachment_state_changes::SubmitAttachmentStateChangesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SubmitAttachmentStateChangesOutputBuilder {
    pub(crate) acknowledgment: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl SubmitAttachmentStateChangesOutputBuilder {
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
    /// Consumes the builder and constructs a [`SubmitAttachmentStateChangesOutput`](crate::operation::submit_attachment_state_changes::SubmitAttachmentStateChangesOutput).
    pub fn build(self) -> crate::operation::submit_attachment_state_changes::SubmitAttachmentStateChangesOutput {
        crate::operation::submit_attachment_state_changes::SubmitAttachmentStateChangesOutput {
            acknowledgment: self.acknowledgment,
            _request_id: self._request_id,
        }
    }
}
