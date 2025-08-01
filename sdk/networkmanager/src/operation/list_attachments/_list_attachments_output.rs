// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAttachmentsOutput {
    /// <p>Describes the list of attachments.</p>
    pub attachments: ::std::option::Option<::std::vec::Vec<crate::types::Attachment>>,
    /// <p>The token for the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAttachmentsOutput {
    /// <p>Describes the list of attachments.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attachments.is_none()`.
    pub fn attachments(&self) -> &[crate::types::Attachment] {
        self.attachments.as_deref().unwrap_or_default()
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListAttachmentsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListAttachmentsOutput {
    /// Creates a new builder-style object to manufacture [`ListAttachmentsOutput`](crate::operation::list_attachments::ListAttachmentsOutput).
    pub fn builder() -> crate::operation::list_attachments::builders::ListAttachmentsOutputBuilder {
        crate::operation::list_attachments::builders::ListAttachmentsOutputBuilder::default()
    }
}

/// A builder for [`ListAttachmentsOutput`](crate::operation::list_attachments::ListAttachmentsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAttachmentsOutputBuilder {
    pub(crate) attachments: ::std::option::Option<::std::vec::Vec<crate::types::Attachment>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListAttachmentsOutputBuilder {
    /// Appends an item to `attachments`.
    ///
    /// To override the contents of this collection use [`set_attachments`](Self::set_attachments).
    ///
    /// <p>Describes the list of attachments.</p>
    pub fn attachments(mut self, input: crate::types::Attachment) -> Self {
        let mut v = self.attachments.unwrap_or_default();
        v.push(input);
        self.attachments = ::std::option::Option::Some(v);
        self
    }
    /// <p>Describes the list of attachments.</p>
    pub fn set_attachments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Attachment>>) -> Self {
        self.attachments = input;
        self
    }
    /// <p>Describes the list of attachments.</p>
    pub fn get_attachments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Attachment>> {
        &self.attachments
    }
    /// <p>The token for the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next page of results.</p>
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
    /// Consumes the builder and constructs a [`ListAttachmentsOutput`](crate::operation::list_attachments::ListAttachmentsOutput).
    pub fn build(self) -> crate::operation::list_attachments::ListAttachmentsOutput {
        crate::operation::list_attachments::ListAttachmentsOutput {
            attachments: self.attachments,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
