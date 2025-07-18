// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelMessageMoveTaskOutput {
    /// <p>The approximate number of messages already moved to the destination queue.</p>
    pub approximate_number_of_messages_moved: i64,
    _request_id: Option<String>,
}
impl CancelMessageMoveTaskOutput {
    /// <p>The approximate number of messages already moved to the destination queue.</p>
    pub fn approximate_number_of_messages_moved(&self) -> i64 {
        self.approximate_number_of_messages_moved
    }
}
impl ::aws_types::request_id::RequestId for CancelMessageMoveTaskOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CancelMessageMoveTaskOutput {
    /// Creates a new builder-style object to manufacture [`CancelMessageMoveTaskOutput`](crate::operation::cancel_message_move_task::CancelMessageMoveTaskOutput).
    pub fn builder() -> crate::operation::cancel_message_move_task::builders::CancelMessageMoveTaskOutputBuilder {
        crate::operation::cancel_message_move_task::builders::CancelMessageMoveTaskOutputBuilder::default()
    }
}

/// A builder for [`CancelMessageMoveTaskOutput`](crate::operation::cancel_message_move_task::CancelMessageMoveTaskOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelMessageMoveTaskOutputBuilder {
    pub(crate) approximate_number_of_messages_moved: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl CancelMessageMoveTaskOutputBuilder {
    /// <p>The approximate number of messages already moved to the destination queue.</p>
    pub fn approximate_number_of_messages_moved(mut self, input: i64) -> Self {
        self.approximate_number_of_messages_moved = ::std::option::Option::Some(input);
        self
    }
    /// <p>The approximate number of messages already moved to the destination queue.</p>
    pub fn set_approximate_number_of_messages_moved(mut self, input: ::std::option::Option<i64>) -> Self {
        self.approximate_number_of_messages_moved = input;
        self
    }
    /// <p>The approximate number of messages already moved to the destination queue.</p>
    pub fn get_approximate_number_of_messages_moved(&self) -> &::std::option::Option<i64> {
        &self.approximate_number_of_messages_moved
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CancelMessageMoveTaskOutput`](crate::operation::cancel_message_move_task::CancelMessageMoveTaskOutput).
    pub fn build(self) -> crate::operation::cancel_message_move_task::CancelMessageMoveTaskOutput {
        crate::operation::cancel_message_move_task::CancelMessageMoveTaskOutput {
            approximate_number_of_messages_moved: self.approximate_number_of_messages_moved.unwrap_or_default(),
            _request_id: self._request_id,
        }
    }
}
