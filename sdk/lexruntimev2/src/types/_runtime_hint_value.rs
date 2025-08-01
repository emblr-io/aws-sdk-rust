// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides the phrase that Amazon Lex V2 should look for in the user's input to the bot.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RuntimeHintValue {
    /// <p>The phrase that Amazon Lex V2 should look for in the user's input to the bot.</p>
    pub phrase: ::std::string::String,
}
impl RuntimeHintValue {
    /// <p>The phrase that Amazon Lex V2 should look for in the user's input to the bot.</p>
    pub fn phrase(&self) -> &str {
        use std::ops::Deref;
        self.phrase.deref()
    }
}
impl RuntimeHintValue {
    /// Creates a new builder-style object to manufacture [`RuntimeHintValue`](crate::types::RuntimeHintValue).
    pub fn builder() -> crate::types::builders::RuntimeHintValueBuilder {
        crate::types::builders::RuntimeHintValueBuilder::default()
    }
}

/// A builder for [`RuntimeHintValue`](crate::types::RuntimeHintValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RuntimeHintValueBuilder {
    pub(crate) phrase: ::std::option::Option<::std::string::String>,
}
impl RuntimeHintValueBuilder {
    /// <p>The phrase that Amazon Lex V2 should look for in the user's input to the bot.</p>
    /// This field is required.
    pub fn phrase(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.phrase = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The phrase that Amazon Lex V2 should look for in the user's input to the bot.</p>
    pub fn set_phrase(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.phrase = input;
        self
    }
    /// <p>The phrase that Amazon Lex V2 should look for in the user's input to the bot.</p>
    pub fn get_phrase(&self) -> &::std::option::Option<::std::string::String> {
        &self.phrase
    }
    /// Consumes the builder and constructs a [`RuntimeHintValue`](crate::types::RuntimeHintValue).
    /// This method will fail if any of the following fields are not set:
    /// - [`phrase`](crate::types::builders::RuntimeHintValueBuilder::phrase)
    pub fn build(self) -> ::std::result::Result<crate::types::RuntimeHintValue, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RuntimeHintValue {
            phrase: self.phrase.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "phrase",
                    "phrase was not specified but it is required when building RuntimeHintValue",
                )
            })?,
        })
    }
}
