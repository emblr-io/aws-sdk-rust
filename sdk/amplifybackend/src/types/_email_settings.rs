// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration for the email sent when an app user forgets their password.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct EmailSettings {
    /// <p>The contents of the email message.</p>
    pub email_message: ::std::option::Option<::std::string::String>,
    /// <p>The contents of the subject line of the email message.</p>
    pub email_subject: ::std::option::Option<::std::string::String>,
}
impl EmailSettings {
    /// <p>The contents of the email message.</p>
    pub fn email_message(&self) -> ::std::option::Option<&str> {
        self.email_message.as_deref()
    }
    /// <p>The contents of the subject line of the email message.</p>
    pub fn email_subject(&self) -> ::std::option::Option<&str> {
        self.email_subject.as_deref()
    }
}
impl ::std::fmt::Debug for EmailSettings {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EmailSettings");
        formatter.field("email_message", &"*** Sensitive Data Redacted ***");
        formatter.field("email_subject", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl EmailSettings {
    /// Creates a new builder-style object to manufacture [`EmailSettings`](crate::types::EmailSettings).
    pub fn builder() -> crate::types::builders::EmailSettingsBuilder {
        crate::types::builders::EmailSettingsBuilder::default()
    }
}

/// A builder for [`EmailSettings`](crate::types::EmailSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct EmailSettingsBuilder {
    pub(crate) email_message: ::std::option::Option<::std::string::String>,
    pub(crate) email_subject: ::std::option::Option<::std::string::String>,
}
impl EmailSettingsBuilder {
    /// <p>The contents of the email message.</p>
    pub fn email_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The contents of the email message.</p>
    pub fn set_email_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_message = input;
        self
    }
    /// <p>The contents of the email message.</p>
    pub fn get_email_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_message
    }
    /// <p>The contents of the subject line of the email message.</p>
    pub fn email_subject(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_subject = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The contents of the subject line of the email message.</p>
    pub fn set_email_subject(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_subject = input;
        self
    }
    /// <p>The contents of the subject line of the email message.</p>
    pub fn get_email_subject(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_subject
    }
    /// Consumes the builder and constructs a [`EmailSettings`](crate::types::EmailSettings).
    pub fn build(self) -> crate::types::EmailSettings {
        crate::types::EmailSettings {
            email_message: self.email_message,
            email_subject: self.email_subject,
        }
    }
}
impl ::std::fmt::Debug for EmailSettingsBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EmailSettingsBuilder");
        formatter.field("email_message", &"*** Sensitive Data Redacted ***");
        formatter.field("email_subject", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
