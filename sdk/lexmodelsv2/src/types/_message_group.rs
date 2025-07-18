// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides one or more messages that Amazon Lex should send to the user.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MessageGroup {
    /// <p>The primary message that Amazon Lex should send to the user.</p>
    pub message: ::std::option::Option<crate::types::Message>,
    /// <p>Message variations to send to the user. When variations are defined, Amazon Lex chooses the primary message or one of the variations to send to the user.</p>
    pub variations: ::std::option::Option<::std::vec::Vec<crate::types::Message>>,
}
impl MessageGroup {
    /// <p>The primary message that Amazon Lex should send to the user.</p>
    pub fn message(&self) -> ::std::option::Option<&crate::types::Message> {
        self.message.as_ref()
    }
    /// <p>Message variations to send to the user. When variations are defined, Amazon Lex chooses the primary message or one of the variations to send to the user.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.variations.is_none()`.
    pub fn variations(&self) -> &[crate::types::Message] {
        self.variations.as_deref().unwrap_or_default()
    }
}
impl MessageGroup {
    /// Creates a new builder-style object to manufacture [`MessageGroup`](crate::types::MessageGroup).
    pub fn builder() -> crate::types::builders::MessageGroupBuilder {
        crate::types::builders::MessageGroupBuilder::default()
    }
}

/// A builder for [`MessageGroup`](crate::types::MessageGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MessageGroupBuilder {
    pub(crate) message: ::std::option::Option<crate::types::Message>,
    pub(crate) variations: ::std::option::Option<::std::vec::Vec<crate::types::Message>>,
}
impl MessageGroupBuilder {
    /// <p>The primary message that Amazon Lex should send to the user.</p>
    /// This field is required.
    pub fn message(mut self, input: crate::types::Message) -> Self {
        self.message = ::std::option::Option::Some(input);
        self
    }
    /// <p>The primary message that Amazon Lex should send to the user.</p>
    pub fn set_message(mut self, input: ::std::option::Option<crate::types::Message>) -> Self {
        self.message = input;
        self
    }
    /// <p>The primary message that Amazon Lex should send to the user.</p>
    pub fn get_message(&self) -> &::std::option::Option<crate::types::Message> {
        &self.message
    }
    /// Appends an item to `variations`.
    ///
    /// To override the contents of this collection use [`set_variations`](Self::set_variations).
    ///
    /// <p>Message variations to send to the user. When variations are defined, Amazon Lex chooses the primary message or one of the variations to send to the user.</p>
    pub fn variations(mut self, input: crate::types::Message) -> Self {
        let mut v = self.variations.unwrap_or_default();
        v.push(input);
        self.variations = ::std::option::Option::Some(v);
        self
    }
    /// <p>Message variations to send to the user. When variations are defined, Amazon Lex chooses the primary message or one of the variations to send to the user.</p>
    pub fn set_variations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Message>>) -> Self {
        self.variations = input;
        self
    }
    /// <p>Message variations to send to the user. When variations are defined, Amazon Lex chooses the primary message or one of the variations to send to the user.</p>
    pub fn get_variations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Message>> {
        &self.variations
    }
    /// Consumes the builder and constructs a [`MessageGroup`](crate::types::MessageGroup).
    pub fn build(self) -> crate::types::MessageGroup {
        crate::types::MessageGroup {
            message: self.message,
            variations: self.variations,
        }
    }
}
