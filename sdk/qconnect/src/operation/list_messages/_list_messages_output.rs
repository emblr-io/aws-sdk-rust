// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMessagesOutput {
    /// <p>The message information.</p>
    pub messages: ::std::vec::Vec<crate::types::MessageOutput>,
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMessagesOutput {
    /// <p>The message information.</p>
    pub fn messages(&self) -> &[crate::types::MessageOutput] {
        use std::ops::Deref;
        self.messages.deref()
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListMessagesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListMessagesOutput {
    /// Creates a new builder-style object to manufacture [`ListMessagesOutput`](crate::operation::list_messages::ListMessagesOutput).
    pub fn builder() -> crate::operation::list_messages::builders::ListMessagesOutputBuilder {
        crate::operation::list_messages::builders::ListMessagesOutputBuilder::default()
    }
}

/// A builder for [`ListMessagesOutput`](crate::operation::list_messages::ListMessagesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMessagesOutputBuilder {
    pub(crate) messages: ::std::option::Option<::std::vec::Vec<crate::types::MessageOutput>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListMessagesOutputBuilder {
    /// Appends an item to `messages`.
    ///
    /// To override the contents of this collection use [`set_messages`](Self::set_messages).
    ///
    /// <p>The message information.</p>
    pub fn messages(mut self, input: crate::types::MessageOutput) -> Self {
        let mut v = self.messages.unwrap_or_default();
        v.push(input);
        self.messages = ::std::option::Option::Some(v);
        self
    }
    /// <p>The message information.</p>
    pub fn set_messages(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MessageOutput>>) -> Self {
        self.messages = input;
        self
    }
    /// <p>The message information.</p>
    pub fn get_messages(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MessageOutput>> {
        &self.messages
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
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
    /// Consumes the builder and constructs a [`ListMessagesOutput`](crate::operation::list_messages::ListMessagesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`messages`](crate::operation::list_messages::builders::ListMessagesOutputBuilder::messages)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_messages::ListMessagesOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_messages::ListMessagesOutput {
            messages: self.messages.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "messages",
                    "messages was not specified but it is required when building ListMessagesOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
