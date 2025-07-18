// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The template for email messages that threat protection sends to a user when your threat protection automated response has a <i>Notify</i> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct NotifyEmailType {
    /// <p>The subject of the threat protection email notification.</p>
    pub subject: ::std::string::String,
    /// <p>The body of an email notification formatted in HTML. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub html_body: ::std::option::Option<::std::string::String>,
    /// <p>The body of an email notification formatted in plaintext. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub text_body: ::std::option::Option<::std::string::String>,
}
impl NotifyEmailType {
    /// <p>The subject of the threat protection email notification.</p>
    pub fn subject(&self) -> &str {
        use std::ops::Deref;
        self.subject.deref()
    }
    /// <p>The body of an email notification formatted in HTML. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub fn html_body(&self) -> ::std::option::Option<&str> {
        self.html_body.as_deref()
    }
    /// <p>The body of an email notification formatted in plaintext. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub fn text_body(&self) -> ::std::option::Option<&str> {
        self.text_body.as_deref()
    }
}
impl NotifyEmailType {
    /// Creates a new builder-style object to manufacture [`NotifyEmailType`](crate::types::NotifyEmailType).
    pub fn builder() -> crate::types::builders::NotifyEmailTypeBuilder {
        crate::types::builders::NotifyEmailTypeBuilder::default()
    }
}

/// A builder for [`NotifyEmailType`](crate::types::NotifyEmailType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct NotifyEmailTypeBuilder {
    pub(crate) subject: ::std::option::Option<::std::string::String>,
    pub(crate) html_body: ::std::option::Option<::std::string::String>,
    pub(crate) text_body: ::std::option::Option<::std::string::String>,
}
impl NotifyEmailTypeBuilder {
    /// <p>The subject of the threat protection email notification.</p>
    /// This field is required.
    pub fn subject(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subject of the threat protection email notification.</p>
    pub fn set_subject(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject = input;
        self
    }
    /// <p>The subject of the threat protection email notification.</p>
    pub fn get_subject(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject
    }
    /// <p>The body of an email notification formatted in HTML. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub fn html_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.html_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The body of an email notification formatted in HTML. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub fn set_html_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.html_body = input;
        self
    }
    /// <p>The body of an email notification formatted in HTML. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub fn get_html_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.html_body
    }
    /// <p>The body of an email notification formatted in plaintext. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub fn text_body(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text_body = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The body of an email notification formatted in plaintext. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub fn set_text_body(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text_body = input;
        self
    }
    /// <p>The body of an email notification formatted in plaintext. Choose an <code>HtmlBody</code> or a <code>TextBody</code> to send an HTML-formatted or plaintext message, respectively.</p>
    pub fn get_text_body(&self) -> &::std::option::Option<::std::string::String> {
        &self.text_body
    }
    /// Consumes the builder and constructs a [`NotifyEmailType`](crate::types::NotifyEmailType).
    /// This method will fail if any of the following fields are not set:
    /// - [`subject`](crate::types::builders::NotifyEmailTypeBuilder::subject)
    pub fn build(self) -> ::std::result::Result<crate::types::NotifyEmailType, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::NotifyEmailType {
            subject: self.subject.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "subject",
                    "subject was not specified but it is required when building NotifyEmailType",
                )
            })?,
            html_body: self.html_body,
            text_body: self.text_body,
        })
    }
}
