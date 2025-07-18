// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the text prompt to optimize.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct TextPrompt {
    /// <p>The text in the text prompt to optimize.</p>
    pub text: ::std::string::String,
}
impl TextPrompt {
    /// <p>The text in the text prompt to optimize.</p>
    pub fn text(&self) -> &str {
        use std::ops::Deref;
        self.text.deref()
    }
}
impl ::std::fmt::Debug for TextPrompt {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TextPrompt");
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl TextPrompt {
    /// Creates a new builder-style object to manufacture [`TextPrompt`](crate::types::TextPrompt).
    pub fn builder() -> crate::types::builders::TextPromptBuilder {
        crate::types::builders::TextPromptBuilder::default()
    }
}

/// A builder for [`TextPrompt`](crate::types::TextPrompt).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct TextPromptBuilder {
    pub(crate) text: ::std::option::Option<::std::string::String>,
}
impl TextPromptBuilder {
    /// <p>The text in the text prompt to optimize.</p>
    /// This field is required.
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text in the text prompt to optimize.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>The text in the text prompt to optimize.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// Consumes the builder and constructs a [`TextPrompt`](crate::types::TextPrompt).
    /// This method will fail if any of the following fields are not set:
    /// - [`text`](crate::types::builders::TextPromptBuilder::text)
    pub fn build(self) -> ::std::result::Result<crate::types::TextPrompt, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TextPrompt {
            text: self.text.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "text",
                    "text was not specified but it is required when building TextPrompt",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for TextPromptBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("TextPromptBuilder");
        formatter.field("text", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
