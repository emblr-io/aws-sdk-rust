// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The textual body content of an email message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MessageBody {
    /// <p>The plain text body content of the message.</p>
    pub text: ::std::option::Option<::std::string::String>,
    /// <p>The HTML body content of the message.</p>
    pub html: ::std::option::Option<::std::string::String>,
    /// <p>A flag indicating if the email was malformed.</p>
    pub message_malformed: ::std::option::Option<bool>,
}
impl MessageBody {
    /// <p>The plain text body content of the message.</p>
    pub fn text(&self) -> ::std::option::Option<&str> {
        self.text.as_deref()
    }
    /// <p>The HTML body content of the message.</p>
    pub fn html(&self) -> ::std::option::Option<&str> {
        self.html.as_deref()
    }
    /// <p>A flag indicating if the email was malformed.</p>
    pub fn message_malformed(&self) -> ::std::option::Option<bool> {
        self.message_malformed
    }
}
impl MessageBody {
    /// Creates a new builder-style object to manufacture [`MessageBody`](crate::types::MessageBody).
    pub fn builder() -> crate::types::builders::MessageBodyBuilder {
        crate::types::builders::MessageBodyBuilder::default()
    }
}

/// A builder for [`MessageBody`](crate::types::MessageBody).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MessageBodyBuilder {
    pub(crate) text: ::std::option::Option<::std::string::String>,
    pub(crate) html: ::std::option::Option<::std::string::String>,
    pub(crate) message_malformed: ::std::option::Option<bool>,
}
impl MessageBodyBuilder {
    /// <p>The plain text body content of the message.</p>
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The plain text body content of the message.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>The plain text body content of the message.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// <p>The HTML body content of the message.</p>
    pub fn html(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.html = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTML body content of the message.</p>
    pub fn set_html(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.html = input;
        self
    }
    /// <p>The HTML body content of the message.</p>
    pub fn get_html(&self) -> &::std::option::Option<::std::string::String> {
        &self.html
    }
    /// <p>A flag indicating if the email was malformed.</p>
    pub fn message_malformed(mut self, input: bool) -> Self {
        self.message_malformed = ::std::option::Option::Some(input);
        self
    }
    /// <p>A flag indicating if the email was malformed.</p>
    pub fn set_message_malformed(mut self, input: ::std::option::Option<bool>) -> Self {
        self.message_malformed = input;
        self
    }
    /// <p>A flag indicating if the email was malformed.</p>
    pub fn get_message_malformed(&self) -> &::std::option::Option<bool> {
        &self.message_malformed
    }
    /// Consumes the builder and constructs a [`MessageBody`](crate::types::MessageBody).
    pub fn build(self) -> crate::types::MessageBody {
        crate::types::MessageBody {
            text: self.text,
            html: self.html,
            message_malformed: self.message_malformed,
        }
    }
}
