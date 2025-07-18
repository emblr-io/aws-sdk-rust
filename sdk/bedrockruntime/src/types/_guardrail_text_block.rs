// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The text block to be evaluated by the guardrail.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GuardrailTextBlock {
    /// <p>The input text details to be evaluated by the guardrail.</p>
    pub text: ::std::string::String,
    /// <p>The qualifiers describing the text block.</p>
    pub qualifiers: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailContentQualifier>>,
}
impl GuardrailTextBlock {
    /// <p>The input text details to be evaluated by the guardrail.</p>
    pub fn text(&self) -> &str {
        use std::ops::Deref;
        self.text.deref()
    }
    /// <p>The qualifiers describing the text block.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.qualifiers.is_none()`.
    pub fn qualifiers(&self) -> &[crate::types::GuardrailContentQualifier] {
        self.qualifiers.as_deref().unwrap_or_default()
    }
}
impl GuardrailTextBlock {
    /// Creates a new builder-style object to manufacture [`GuardrailTextBlock`](crate::types::GuardrailTextBlock).
    pub fn builder() -> crate::types::builders::GuardrailTextBlockBuilder {
        crate::types::builders::GuardrailTextBlockBuilder::default()
    }
}

/// A builder for [`GuardrailTextBlock`](crate::types::GuardrailTextBlock).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GuardrailTextBlockBuilder {
    pub(crate) text: ::std::option::Option<::std::string::String>,
    pub(crate) qualifiers: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailContentQualifier>>,
}
impl GuardrailTextBlockBuilder {
    /// <p>The input text details to be evaluated by the guardrail.</p>
    /// This field is required.
    pub fn text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The input text details to be evaluated by the guardrail.</p>
    pub fn set_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text = input;
        self
    }
    /// <p>The input text details to be evaluated by the guardrail.</p>
    pub fn get_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.text
    }
    /// Appends an item to `qualifiers`.
    ///
    /// To override the contents of this collection use [`set_qualifiers`](Self::set_qualifiers).
    ///
    /// <p>The qualifiers describing the text block.</p>
    pub fn qualifiers(mut self, input: crate::types::GuardrailContentQualifier) -> Self {
        let mut v = self.qualifiers.unwrap_or_default();
        v.push(input);
        self.qualifiers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The qualifiers describing the text block.</p>
    pub fn set_qualifiers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::GuardrailContentQualifier>>) -> Self {
        self.qualifiers = input;
        self
    }
    /// <p>The qualifiers describing the text block.</p>
    pub fn get_qualifiers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::GuardrailContentQualifier>> {
        &self.qualifiers
    }
    /// Consumes the builder and constructs a [`GuardrailTextBlock`](crate::types::GuardrailTextBlock).
    /// This method will fail if any of the following fields are not set:
    /// - [`text`](crate::types::builders::GuardrailTextBlockBuilder::text)
    pub fn build(self) -> ::std::result::Result<crate::types::GuardrailTextBlock, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::GuardrailTextBlock {
            text: self.text.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "text",
                    "text was not specified but it is required when building GuardrailTextBlock",
                )
            })?,
            qualifiers: self.qualifiers,
        })
    }
}
