// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The conditional formatting of a <code>FilledMapVisual</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilledMapConditionalFormatting {
    /// <p>Conditional formatting options of a <code>FilledMapVisual</code>.</p>
    pub conditional_formatting_options: ::std::vec::Vec<crate::types::FilledMapConditionalFormattingOption>,
}
impl FilledMapConditionalFormatting {
    /// <p>Conditional formatting options of a <code>FilledMapVisual</code>.</p>
    pub fn conditional_formatting_options(&self) -> &[crate::types::FilledMapConditionalFormattingOption] {
        use std::ops::Deref;
        self.conditional_formatting_options.deref()
    }
}
impl FilledMapConditionalFormatting {
    /// Creates a new builder-style object to manufacture [`FilledMapConditionalFormatting`](crate::types::FilledMapConditionalFormatting).
    pub fn builder() -> crate::types::builders::FilledMapConditionalFormattingBuilder {
        crate::types::builders::FilledMapConditionalFormattingBuilder::default()
    }
}

/// A builder for [`FilledMapConditionalFormatting`](crate::types::FilledMapConditionalFormatting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilledMapConditionalFormattingBuilder {
    pub(crate) conditional_formatting_options: ::std::option::Option<::std::vec::Vec<crate::types::FilledMapConditionalFormattingOption>>,
}
impl FilledMapConditionalFormattingBuilder {
    /// Appends an item to `conditional_formatting_options`.
    ///
    /// To override the contents of this collection use [`set_conditional_formatting_options`](Self::set_conditional_formatting_options).
    ///
    /// <p>Conditional formatting options of a <code>FilledMapVisual</code>.</p>
    pub fn conditional_formatting_options(mut self, input: crate::types::FilledMapConditionalFormattingOption) -> Self {
        let mut v = self.conditional_formatting_options.unwrap_or_default();
        v.push(input);
        self.conditional_formatting_options = ::std::option::Option::Some(v);
        self
    }
    /// <p>Conditional formatting options of a <code>FilledMapVisual</code>.</p>
    pub fn set_conditional_formatting_options(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::FilledMapConditionalFormattingOption>>,
    ) -> Self {
        self.conditional_formatting_options = input;
        self
    }
    /// <p>Conditional formatting options of a <code>FilledMapVisual</code>.</p>
    pub fn get_conditional_formatting_options(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FilledMapConditionalFormattingOption>> {
        &self.conditional_formatting_options
    }
    /// Consumes the builder and constructs a [`FilledMapConditionalFormatting`](crate::types::FilledMapConditionalFormatting).
    /// This method will fail if any of the following fields are not set:
    /// - [`conditional_formatting_options`](crate::types::builders::FilledMapConditionalFormattingBuilder::conditional_formatting_options)
    pub fn build(self) -> ::std::result::Result<crate::types::FilledMapConditionalFormatting, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FilledMapConditionalFormatting {
            conditional_formatting_options: self.conditional_formatting_options.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "conditional_formatting_options",
                    "conditional_formatting_options was not specified but it is required when building FilledMapConditionalFormatting",
                )
            })?,
        })
    }
}
