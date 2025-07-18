// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct RenderMessageTemplateOutput {
    /// <p>The content of the message template.</p>
    pub content: ::std::option::Option<crate::types::MessageTemplateContentProvider>,
    /// <p>The attribute keys that are not resolved.</p>
    pub attributes_not_interpolated: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The message template attachments.</p>
    pub attachments: ::std::option::Option<::std::vec::Vec<crate::types::MessageTemplateAttachment>>,
    _request_id: Option<String>,
}
impl RenderMessageTemplateOutput {
    /// <p>The content of the message template.</p>
    pub fn content(&self) -> ::std::option::Option<&crate::types::MessageTemplateContentProvider> {
        self.content.as_ref()
    }
    /// <p>The attribute keys that are not resolved.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attributes_not_interpolated.is_none()`.
    pub fn attributes_not_interpolated(&self) -> &[::std::string::String] {
        self.attributes_not_interpolated.as_deref().unwrap_or_default()
    }
    /// <p>The message template attachments.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.attachments.is_none()`.
    pub fn attachments(&self) -> &[crate::types::MessageTemplateAttachment] {
        self.attachments.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for RenderMessageTemplateOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RenderMessageTemplateOutput");
        formatter.field("content", &self.content);
        formatter.field("attributes_not_interpolated", &"*** Sensitive Data Redacted ***");
        formatter.field("attachments", &self.attachments);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for RenderMessageTemplateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RenderMessageTemplateOutput {
    /// Creates a new builder-style object to manufacture [`RenderMessageTemplateOutput`](crate::operation::render_message_template::RenderMessageTemplateOutput).
    pub fn builder() -> crate::operation::render_message_template::builders::RenderMessageTemplateOutputBuilder {
        crate::operation::render_message_template::builders::RenderMessageTemplateOutputBuilder::default()
    }
}

/// A builder for [`RenderMessageTemplateOutput`](crate::operation::render_message_template::RenderMessageTemplateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct RenderMessageTemplateOutputBuilder {
    pub(crate) content: ::std::option::Option<crate::types::MessageTemplateContentProvider>,
    pub(crate) attributes_not_interpolated: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) attachments: ::std::option::Option<::std::vec::Vec<crate::types::MessageTemplateAttachment>>,
    _request_id: Option<String>,
}
impl RenderMessageTemplateOutputBuilder {
    /// <p>The content of the message template.</p>
    /// This field is required.
    pub fn content(mut self, input: crate::types::MessageTemplateContentProvider) -> Self {
        self.content = ::std::option::Option::Some(input);
        self
    }
    /// <p>The content of the message template.</p>
    pub fn set_content(mut self, input: ::std::option::Option<crate::types::MessageTemplateContentProvider>) -> Self {
        self.content = input;
        self
    }
    /// <p>The content of the message template.</p>
    pub fn get_content(&self) -> &::std::option::Option<crate::types::MessageTemplateContentProvider> {
        &self.content
    }
    /// Appends an item to `attributes_not_interpolated`.
    ///
    /// To override the contents of this collection use [`set_attributes_not_interpolated`](Self::set_attributes_not_interpolated).
    ///
    /// <p>The attribute keys that are not resolved.</p>
    pub fn attributes_not_interpolated(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.attributes_not_interpolated.unwrap_or_default();
        v.push(input.into());
        self.attributes_not_interpolated = ::std::option::Option::Some(v);
        self
    }
    /// <p>The attribute keys that are not resolved.</p>
    pub fn set_attributes_not_interpolated(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.attributes_not_interpolated = input;
        self
    }
    /// <p>The attribute keys that are not resolved.</p>
    pub fn get_attributes_not_interpolated(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.attributes_not_interpolated
    }
    /// Appends an item to `attachments`.
    ///
    /// To override the contents of this collection use [`set_attachments`](Self::set_attachments).
    ///
    /// <p>The message template attachments.</p>
    pub fn attachments(mut self, input: crate::types::MessageTemplateAttachment) -> Self {
        let mut v = self.attachments.unwrap_or_default();
        v.push(input);
        self.attachments = ::std::option::Option::Some(v);
        self
    }
    /// <p>The message template attachments.</p>
    pub fn set_attachments(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MessageTemplateAttachment>>) -> Self {
        self.attachments = input;
        self
    }
    /// <p>The message template attachments.</p>
    pub fn get_attachments(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MessageTemplateAttachment>> {
        &self.attachments
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RenderMessageTemplateOutput`](crate::operation::render_message_template::RenderMessageTemplateOutput).
    pub fn build(self) -> crate::operation::render_message_template::RenderMessageTemplateOutput {
        crate::operation::render_message_template::RenderMessageTemplateOutput {
            content: self.content,
            attributes_not_interpolated: self.attributes_not_interpolated,
            attachments: self.attachments,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for RenderMessageTemplateOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("RenderMessageTemplateOutputBuilder");
        formatter.field("content", &self.content);
        formatter.field("attributes_not_interpolated", &"*** Sensitive Data Redacted ***");
        formatter.field("attachments", &self.attachments);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
