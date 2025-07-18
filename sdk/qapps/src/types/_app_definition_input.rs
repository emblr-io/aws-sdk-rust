// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The input for defining an Q App.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AppDefinitionInput {
    /// <p>The cards that make up the Q App definition.</p>
    pub cards: ::std::vec::Vec<crate::types::CardInput>,
    /// <p>The initial prompt displayed when the Q App is started.</p>
    pub initial_prompt: ::std::option::Option<::std::string::String>,
}
impl AppDefinitionInput {
    /// <p>The cards that make up the Q App definition.</p>
    pub fn cards(&self) -> &[crate::types::CardInput] {
        use std::ops::Deref;
        self.cards.deref()
    }
    /// <p>The initial prompt displayed when the Q App is started.</p>
    pub fn initial_prompt(&self) -> ::std::option::Option<&str> {
        self.initial_prompt.as_deref()
    }
}
impl AppDefinitionInput {
    /// Creates a new builder-style object to manufacture [`AppDefinitionInput`](crate::types::AppDefinitionInput).
    pub fn builder() -> crate::types::builders::AppDefinitionInputBuilder {
        crate::types::builders::AppDefinitionInputBuilder::default()
    }
}

/// A builder for [`AppDefinitionInput`](crate::types::AppDefinitionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AppDefinitionInputBuilder {
    pub(crate) cards: ::std::option::Option<::std::vec::Vec<crate::types::CardInput>>,
    pub(crate) initial_prompt: ::std::option::Option<::std::string::String>,
}
impl AppDefinitionInputBuilder {
    /// Appends an item to `cards`.
    ///
    /// To override the contents of this collection use [`set_cards`](Self::set_cards).
    ///
    /// <p>The cards that make up the Q App definition.</p>
    pub fn cards(mut self, input: crate::types::CardInput) -> Self {
        let mut v = self.cards.unwrap_or_default();
        v.push(input);
        self.cards = ::std::option::Option::Some(v);
        self
    }
    /// <p>The cards that make up the Q App definition.</p>
    pub fn set_cards(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CardInput>>) -> Self {
        self.cards = input;
        self
    }
    /// <p>The cards that make up the Q App definition.</p>
    pub fn get_cards(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CardInput>> {
        &self.cards
    }
    /// <p>The initial prompt displayed when the Q App is started.</p>
    pub fn initial_prompt(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.initial_prompt = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The initial prompt displayed when the Q App is started.</p>
    pub fn set_initial_prompt(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.initial_prompt = input;
        self
    }
    /// <p>The initial prompt displayed when the Q App is started.</p>
    pub fn get_initial_prompt(&self) -> &::std::option::Option<::std::string::String> {
        &self.initial_prompt
    }
    /// Consumes the builder and constructs a [`AppDefinitionInput`](crate::types::AppDefinitionInput).
    /// This method will fail if any of the following fields are not set:
    /// - [`cards`](crate::types::builders::AppDefinitionInputBuilder::cards)
    pub fn build(self) -> ::std::result::Result<crate::types::AppDefinitionInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AppDefinitionInput {
            cards: self.cards.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "cards",
                    "cards was not specified but it is required when building AppDefinitionInput",
                )
            })?,
            initial_prompt: self.initial_prompt,
        })
    }
}
