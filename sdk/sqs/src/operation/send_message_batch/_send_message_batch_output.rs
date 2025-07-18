// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>For each message in the batch, the response contains a <code> <code>SendMessageBatchResultEntry</code> </code> tag if the message succeeds or a <code> <code>BatchResultErrorEntry</code> </code> tag if the message fails.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendMessageBatchOutput {
    /// <p>A list of <code> <code>SendMessageBatchResultEntry</code> </code> items.</p>
    pub successful: ::std::vec::Vec<crate::types::SendMessageBatchResultEntry>,
    /// <p>A list of <code> <code>BatchResultErrorEntry</code> </code> items with error details about each message that can't be enqueued.</p>
    pub failed: ::std::vec::Vec<crate::types::BatchResultErrorEntry>,
    _request_id: Option<String>,
}
impl SendMessageBatchOutput {
    /// <p>A list of <code> <code>SendMessageBatchResultEntry</code> </code> items.</p>
    pub fn successful(&self) -> &[crate::types::SendMessageBatchResultEntry] {
        use std::ops::Deref;
        self.successful.deref()
    }
    /// <p>A list of <code> <code>BatchResultErrorEntry</code> </code> items with error details about each message that can't be enqueued.</p>
    pub fn failed(&self) -> &[crate::types::BatchResultErrorEntry] {
        use std::ops::Deref;
        self.failed.deref()
    }
}
impl ::aws_types::request_id::RequestId for SendMessageBatchOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SendMessageBatchOutput {
    /// Creates a new builder-style object to manufacture [`SendMessageBatchOutput`](crate::operation::send_message_batch::SendMessageBatchOutput).
    pub fn builder() -> crate::operation::send_message_batch::builders::SendMessageBatchOutputBuilder {
        crate::operation::send_message_batch::builders::SendMessageBatchOutputBuilder::default()
    }
}

/// A builder for [`SendMessageBatchOutput`](crate::operation::send_message_batch::SendMessageBatchOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendMessageBatchOutputBuilder {
    pub(crate) successful: ::std::option::Option<::std::vec::Vec<crate::types::SendMessageBatchResultEntry>>,
    pub(crate) failed: ::std::option::Option<::std::vec::Vec<crate::types::BatchResultErrorEntry>>,
    _request_id: Option<String>,
}
impl SendMessageBatchOutputBuilder {
    /// Appends an item to `successful`.
    ///
    /// To override the contents of this collection use [`set_successful`](Self::set_successful).
    ///
    /// <p>A list of <code> <code>SendMessageBatchResultEntry</code> </code> items.</p>
    pub fn successful(mut self, input: crate::types::SendMessageBatchResultEntry) -> Self {
        let mut v = self.successful.unwrap_or_default();
        v.push(input);
        self.successful = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code> <code>SendMessageBatchResultEntry</code> </code> items.</p>
    pub fn set_successful(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SendMessageBatchResultEntry>>) -> Self {
        self.successful = input;
        self
    }
    /// <p>A list of <code> <code>SendMessageBatchResultEntry</code> </code> items.</p>
    pub fn get_successful(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SendMessageBatchResultEntry>> {
        &self.successful
    }
    /// Appends an item to `failed`.
    ///
    /// To override the contents of this collection use [`set_failed`](Self::set_failed).
    ///
    /// <p>A list of <code> <code>BatchResultErrorEntry</code> </code> items with error details about each message that can't be enqueued.</p>
    pub fn failed(mut self, input: crate::types::BatchResultErrorEntry) -> Self {
        let mut v = self.failed.unwrap_or_default();
        v.push(input);
        self.failed = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code> <code>BatchResultErrorEntry</code> </code> items with error details about each message that can't be enqueued.</p>
    pub fn set_failed(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BatchResultErrorEntry>>) -> Self {
        self.failed = input;
        self
    }
    /// <p>A list of <code> <code>BatchResultErrorEntry</code> </code> items with error details about each message that can't be enqueued.</p>
    pub fn get_failed(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchResultErrorEntry>> {
        &self.failed
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SendMessageBatchOutput`](crate::operation::send_message_batch::SendMessageBatchOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`successful`](crate::operation::send_message_batch::builders::SendMessageBatchOutputBuilder::successful)
    /// - [`failed`](crate::operation::send_message_batch::builders::SendMessageBatchOutputBuilder::failed)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::send_message_batch::SendMessageBatchOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::send_message_batch::SendMessageBatchOutput {
            successful: self.successful.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "successful",
                    "successful was not specified but it is required when building SendMessageBatchOutput",
                )
            })?,
            failed: self.failed.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "failed",
                    "failed was not specified but it is required when building SendMessageBatchOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
