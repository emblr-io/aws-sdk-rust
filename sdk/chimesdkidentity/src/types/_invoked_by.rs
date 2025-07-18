// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the type of message that triggers a bot.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InvokedBy {
    /// <p>Sets standard messages as the bot trigger. For standard messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all standard messages.</p></li>
    /// <li>
    /// <p><code>AUTO</code>: The bot responds to ALL messages when the channel has one other non-hidden member, and responds to MENTIONS when the channel has more than one other non-hidden member.</p></li>
    /// <li>
    /// <p><code>MENTIONS</code>: The bot processes all standard messages that have a message attribute with <code>CHIME.mentions</code> and a value of the bot ARN.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no standard messages.</p></li>
    /// </ul>
    pub standard_messages: crate::types::StandardMessages,
    /// <p>Sets targeted messages as the bot trigger. For targeted messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all <code>TargetedMessages</code> sent to it. The bot then responds with a targeted message back to the sender.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no targeted messages.</p></li>
    /// </ul>
    pub targeted_messages: crate::types::TargetedMessages,
}
impl InvokedBy {
    /// <p>Sets standard messages as the bot trigger. For standard messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all standard messages.</p></li>
    /// <li>
    /// <p><code>AUTO</code>: The bot responds to ALL messages when the channel has one other non-hidden member, and responds to MENTIONS when the channel has more than one other non-hidden member.</p></li>
    /// <li>
    /// <p><code>MENTIONS</code>: The bot processes all standard messages that have a message attribute with <code>CHIME.mentions</code> and a value of the bot ARN.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no standard messages.</p></li>
    /// </ul>
    pub fn standard_messages(&self) -> &crate::types::StandardMessages {
        &self.standard_messages
    }
    /// <p>Sets targeted messages as the bot trigger. For targeted messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all <code>TargetedMessages</code> sent to it. The bot then responds with a targeted message back to the sender.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no targeted messages.</p></li>
    /// </ul>
    pub fn targeted_messages(&self) -> &crate::types::TargetedMessages {
        &self.targeted_messages
    }
}
impl InvokedBy {
    /// Creates a new builder-style object to manufacture [`InvokedBy`](crate::types::InvokedBy).
    pub fn builder() -> crate::types::builders::InvokedByBuilder {
        crate::types::builders::InvokedByBuilder::default()
    }
}

/// A builder for [`InvokedBy`](crate::types::InvokedBy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InvokedByBuilder {
    pub(crate) standard_messages: ::std::option::Option<crate::types::StandardMessages>,
    pub(crate) targeted_messages: ::std::option::Option<crate::types::TargetedMessages>,
}
impl InvokedByBuilder {
    /// <p>Sets standard messages as the bot trigger. For standard messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all standard messages.</p></li>
    /// <li>
    /// <p><code>AUTO</code>: The bot responds to ALL messages when the channel has one other non-hidden member, and responds to MENTIONS when the channel has more than one other non-hidden member.</p></li>
    /// <li>
    /// <p><code>MENTIONS</code>: The bot processes all standard messages that have a message attribute with <code>CHIME.mentions</code> and a value of the bot ARN.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no standard messages.</p></li>
    /// </ul>
    /// This field is required.
    pub fn standard_messages(mut self, input: crate::types::StandardMessages) -> Self {
        self.standard_messages = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets standard messages as the bot trigger. For standard messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all standard messages.</p></li>
    /// <li>
    /// <p><code>AUTO</code>: The bot responds to ALL messages when the channel has one other non-hidden member, and responds to MENTIONS when the channel has more than one other non-hidden member.</p></li>
    /// <li>
    /// <p><code>MENTIONS</code>: The bot processes all standard messages that have a message attribute with <code>CHIME.mentions</code> and a value of the bot ARN.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no standard messages.</p></li>
    /// </ul>
    pub fn set_standard_messages(mut self, input: ::std::option::Option<crate::types::StandardMessages>) -> Self {
        self.standard_messages = input;
        self
    }
    /// <p>Sets standard messages as the bot trigger. For standard messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all standard messages.</p></li>
    /// <li>
    /// <p><code>AUTO</code>: The bot responds to ALL messages when the channel has one other non-hidden member, and responds to MENTIONS when the channel has more than one other non-hidden member.</p></li>
    /// <li>
    /// <p><code>MENTIONS</code>: The bot processes all standard messages that have a message attribute with <code>CHIME.mentions</code> and a value of the bot ARN.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no standard messages.</p></li>
    /// </ul>
    pub fn get_standard_messages(&self) -> &::std::option::Option<crate::types::StandardMessages> {
        &self.standard_messages
    }
    /// <p>Sets targeted messages as the bot trigger. For targeted messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all <code>TargetedMessages</code> sent to it. The bot then responds with a targeted message back to the sender.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no targeted messages.</p></li>
    /// </ul>
    /// This field is required.
    pub fn targeted_messages(mut self, input: crate::types::TargetedMessages) -> Self {
        self.targeted_messages = ::std::option::Option::Some(input);
        self
    }
    /// <p>Sets targeted messages as the bot trigger. For targeted messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all <code>TargetedMessages</code> sent to it. The bot then responds with a targeted message back to the sender.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no targeted messages.</p></li>
    /// </ul>
    pub fn set_targeted_messages(mut self, input: ::std::option::Option<crate::types::TargetedMessages>) -> Self {
        self.targeted_messages = input;
        self
    }
    /// <p>Sets targeted messages as the bot trigger. For targeted messages:</p>
    /// <ul>
    /// <li>
    /// <p><code>ALL</code>: The bot processes all <code>TargetedMessages</code> sent to it. The bot then responds with a targeted message back to the sender.</p></li>
    /// <li>
    /// <p><code>NONE</code>: The bot processes no targeted messages.</p></li>
    /// </ul>
    pub fn get_targeted_messages(&self) -> &::std::option::Option<crate::types::TargetedMessages> {
        &self.targeted_messages
    }
    /// Consumes the builder and constructs a [`InvokedBy`](crate::types::InvokedBy).
    /// This method will fail if any of the following fields are not set:
    /// - [`standard_messages`](crate::types::builders::InvokedByBuilder::standard_messages)
    /// - [`targeted_messages`](crate::types::builders::InvokedByBuilder::targeted_messages)
    pub fn build(self) -> ::std::result::Result<crate::types::InvokedBy, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InvokedBy {
            standard_messages: self.standard_messages.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "standard_messages",
                    "standard_messages was not specified but it is required when building InvokedBy",
                )
            })?,
            targeted_messages: self.targeted_messages.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "targeted_messages",
                    "targeted_messages was not specified but it is required when building InvokedBy",
                )
            })?,
        })
    }
}
