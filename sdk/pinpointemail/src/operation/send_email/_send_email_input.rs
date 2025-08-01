// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to send an email message.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendEmailInput {
    /// <p>The email address that you want to use as the "From" address for the email. The address that you specify has to be verified.</p>
    pub from_email_address: ::std::option::Option<::std::string::String>,
    /// <p>An object that contains the recipients of the email message.</p>
    pub destination: ::std::option::Option<crate::types::Destination>,
    /// <p>The "Reply-to" email addresses for the message. When the recipient replies to the message, each Reply-to address receives the reply.</p>
    pub reply_to_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The address that Amazon Pinpoint should send bounce and complaint notifications to.</p>
    pub feedback_forwarding_email_address: ::std::option::Option<::std::string::String>,
    /// <p>An object that contains the body of the message. You can send either a Simple message or a Raw message.</p>
    pub content: ::std::option::Option<crate::types::EmailContent>,
    /// <p>A list of tags, in the form of name/value pairs, to apply to an email that you send using the <code>SendEmail</code> operation. Tags correspond to characteristics of the email that you define, so that you can publish email sending events.</p>
    pub email_tags: ::std::option::Option<::std::vec::Vec<crate::types::MessageTag>>,
    /// <p>The name of the configuration set that you want to use when sending the email.</p>
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
}
impl SendEmailInput {
    /// <p>The email address that you want to use as the "From" address for the email. The address that you specify has to be verified.</p>
    pub fn from_email_address(&self) -> ::std::option::Option<&str> {
        self.from_email_address.as_deref()
    }
    /// <p>An object that contains the recipients of the email message.</p>
    pub fn destination(&self) -> ::std::option::Option<&crate::types::Destination> {
        self.destination.as_ref()
    }
    /// <p>The "Reply-to" email addresses for the message. When the recipient replies to the message, each Reply-to address receives the reply.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.reply_to_addresses.is_none()`.
    pub fn reply_to_addresses(&self) -> &[::std::string::String] {
        self.reply_to_addresses.as_deref().unwrap_or_default()
    }
    /// <p>The address that Amazon Pinpoint should send bounce and complaint notifications to.</p>
    pub fn feedback_forwarding_email_address(&self) -> ::std::option::Option<&str> {
        self.feedback_forwarding_email_address.as_deref()
    }
    /// <p>An object that contains the body of the message. You can send either a Simple message or a Raw message.</p>
    pub fn content(&self) -> ::std::option::Option<&crate::types::EmailContent> {
        self.content.as_ref()
    }
    /// <p>A list of tags, in the form of name/value pairs, to apply to an email that you send using the <code>SendEmail</code> operation. Tags correspond to characteristics of the email that you define, so that you can publish email sending events.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.email_tags.is_none()`.
    pub fn email_tags(&self) -> &[crate::types::MessageTag] {
        self.email_tags.as_deref().unwrap_or_default()
    }
    /// <p>The name of the configuration set that you want to use when sending the email.</p>
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
}
impl SendEmailInput {
    /// Creates a new builder-style object to manufacture [`SendEmailInput`](crate::operation::send_email::SendEmailInput).
    pub fn builder() -> crate::operation::send_email::builders::SendEmailInputBuilder {
        crate::operation::send_email::builders::SendEmailInputBuilder::default()
    }
}

/// A builder for [`SendEmailInput`](crate::operation::send_email::SendEmailInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendEmailInputBuilder {
    pub(crate) from_email_address: ::std::option::Option<::std::string::String>,
    pub(crate) destination: ::std::option::Option<crate::types::Destination>,
    pub(crate) reply_to_addresses: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) feedback_forwarding_email_address: ::std::option::Option<::std::string::String>,
    pub(crate) content: ::std::option::Option<crate::types::EmailContent>,
    pub(crate) email_tags: ::std::option::Option<::std::vec::Vec<crate::types::MessageTag>>,
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
}
impl SendEmailInputBuilder {
    /// <p>The email address that you want to use as the "From" address for the email. The address that you specify has to be verified.</p>
    pub fn from_email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.from_email_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address that you want to use as the "From" address for the email. The address that you specify has to be verified.</p>
    pub fn set_from_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.from_email_address = input;
        self
    }
    /// <p>The email address that you want to use as the "From" address for the email. The address that you specify has to be verified.</p>
    pub fn get_from_email_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.from_email_address
    }
    /// <p>An object that contains the recipients of the email message.</p>
    /// This field is required.
    pub fn destination(mut self, input: crate::types::Destination) -> Self {
        self.destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains the recipients of the email message.</p>
    pub fn set_destination(mut self, input: ::std::option::Option<crate::types::Destination>) -> Self {
        self.destination = input;
        self
    }
    /// <p>An object that contains the recipients of the email message.</p>
    pub fn get_destination(&self) -> &::std::option::Option<crate::types::Destination> {
        &self.destination
    }
    /// Appends an item to `reply_to_addresses`.
    ///
    /// To override the contents of this collection use [`set_reply_to_addresses`](Self::set_reply_to_addresses).
    ///
    /// <p>The "Reply-to" email addresses for the message. When the recipient replies to the message, each Reply-to address receives the reply.</p>
    pub fn reply_to_addresses(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.reply_to_addresses.unwrap_or_default();
        v.push(input.into());
        self.reply_to_addresses = ::std::option::Option::Some(v);
        self
    }
    /// <p>The "Reply-to" email addresses for the message. When the recipient replies to the message, each Reply-to address receives the reply.</p>
    pub fn set_reply_to_addresses(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.reply_to_addresses = input;
        self
    }
    /// <p>The "Reply-to" email addresses for the message. When the recipient replies to the message, each Reply-to address receives the reply.</p>
    pub fn get_reply_to_addresses(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.reply_to_addresses
    }
    /// <p>The address that Amazon Pinpoint should send bounce and complaint notifications to.</p>
    pub fn feedback_forwarding_email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.feedback_forwarding_email_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The address that Amazon Pinpoint should send bounce and complaint notifications to.</p>
    pub fn set_feedback_forwarding_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.feedback_forwarding_email_address = input;
        self
    }
    /// <p>The address that Amazon Pinpoint should send bounce and complaint notifications to.</p>
    pub fn get_feedback_forwarding_email_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.feedback_forwarding_email_address
    }
    /// <p>An object that contains the body of the message. You can send either a Simple message or a Raw message.</p>
    /// This field is required.
    pub fn content(mut self, input: crate::types::EmailContent) -> Self {
        self.content = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains the body of the message. You can send either a Simple message or a Raw message.</p>
    pub fn set_content(mut self, input: ::std::option::Option<crate::types::EmailContent>) -> Self {
        self.content = input;
        self
    }
    /// <p>An object that contains the body of the message. You can send either a Simple message or a Raw message.</p>
    pub fn get_content(&self) -> &::std::option::Option<crate::types::EmailContent> {
        &self.content
    }
    /// Appends an item to `email_tags`.
    ///
    /// To override the contents of this collection use [`set_email_tags`](Self::set_email_tags).
    ///
    /// <p>A list of tags, in the form of name/value pairs, to apply to an email that you send using the <code>SendEmail</code> operation. Tags correspond to characteristics of the email that you define, so that you can publish email sending events.</p>
    pub fn email_tags(mut self, input: crate::types::MessageTag) -> Self {
        let mut v = self.email_tags.unwrap_or_default();
        v.push(input);
        self.email_tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags, in the form of name/value pairs, to apply to an email that you send using the <code>SendEmail</code> operation. Tags correspond to characteristics of the email that you define, so that you can publish email sending events.</p>
    pub fn set_email_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MessageTag>>) -> Self {
        self.email_tags = input;
        self
    }
    /// <p>A list of tags, in the form of name/value pairs, to apply to an email that you send using the <code>SendEmail</code> operation. Tags correspond to characteristics of the email that you define, so that you can publish email sending events.</p>
    pub fn get_email_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MessageTag>> {
        &self.email_tags
    }
    /// <p>The name of the configuration set that you want to use when sending the email.</p>
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration set that you want to use when sending the email.</p>
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// <p>The name of the configuration set that you want to use when sending the email.</p>
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
    }
    /// Consumes the builder and constructs a [`SendEmailInput`](crate::operation::send_email::SendEmailInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::send_email::SendEmailInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::send_email::SendEmailInput {
            from_email_address: self.from_email_address,
            destination: self.destination,
            reply_to_addresses: self.reply_to_addresses,
            feedback_forwarding_email_address: self.feedback_forwarding_email_address,
            content: self.content,
            email_tags: self.email_tags,
            configuration_set_name: self.configuration_set_name,
        })
    }
}
