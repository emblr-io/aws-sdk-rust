// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the subject and message of an email.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EmailContent {
    /// <p>The subject of the email.</p>
    pub subject: ::std::option::Option<::std::string::String>,
    /// <p>The message that you want to send. The message can be up to 200 characters.</p>
    pub additional_message: ::std::option::Option<::std::string::String>,
}
impl EmailContent {
    /// <p>The subject of the email.</p>
    pub fn subject(&self) -> ::std::option::Option<&str> {
        self.subject.as_deref()
    }
    /// <p>The message that you want to send. The message can be up to 200 characters.</p>
    pub fn additional_message(&self) -> ::std::option::Option<&str> {
        self.additional_message.as_deref()
    }
}
impl EmailContent {
    /// Creates a new builder-style object to manufacture [`EmailContent`](crate::types::EmailContent).
    pub fn builder() -> crate::types::builders::EmailContentBuilder {
        crate::types::builders::EmailContentBuilder::default()
    }
}

/// A builder for [`EmailContent`](crate::types::EmailContent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EmailContentBuilder {
    pub(crate) subject: ::std::option::Option<::std::string::String>,
    pub(crate) additional_message: ::std::option::Option<::std::string::String>,
}
impl EmailContentBuilder {
    /// <p>The subject of the email.</p>
    pub fn subject(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subject = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The subject of the email.</p>
    pub fn set_subject(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subject = input;
        self
    }
    /// <p>The subject of the email.</p>
    pub fn get_subject(&self) -> &::std::option::Option<::std::string::String> {
        &self.subject
    }
    /// <p>The message that you want to send. The message can be up to 200 characters.</p>
    pub fn additional_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.additional_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message that you want to send. The message can be up to 200 characters.</p>
    pub fn set_additional_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.additional_message = input;
        self
    }
    /// <p>The message that you want to send. The message can be up to 200 characters.</p>
    pub fn get_additional_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.additional_message
    }
    /// Consumes the builder and constructs a [`EmailContent`](crate::types::EmailContent).
    pub fn build(self) -> crate::types::EmailContent {
        crate::types::EmailContent {
            subject: self.subject,
            additional_message: self.additional_message,
        }
    }
}
