// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The conditional formatting for a <code>PivotTableVisual</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TableConditionalFormatting {
    /// <p>Conditional formatting options for a <code>PivotTableVisual</code>.</p>
    pub conditional_formatting_options: ::std::option::Option<::std::vec::Vec<crate::types::TableConditionalFormattingOption>>,
}
impl TableConditionalFormatting {
    /// <p>Conditional formatting options for a <code>PivotTableVisual</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.conditional_formatting_options.is_none()`.
    pub fn conditional_formatting_options(&self) -> &[crate::types::TableConditionalFormattingOption] {
        self.conditional_formatting_options.as_deref().unwrap_or_default()
    }
}
impl TableConditionalFormatting {
    /// Creates a new builder-style object to manufacture [`TableConditionalFormatting`](crate::types::TableConditionalFormatting).
    pub fn builder() -> crate::types::builders::TableConditionalFormattingBuilder {
        crate::types::builders::TableConditionalFormattingBuilder::default()
    }
}

/// A builder for [`TableConditionalFormatting`](crate::types::TableConditionalFormatting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TableConditionalFormattingBuilder {
    pub(crate) conditional_formatting_options: ::std::option::Option<::std::vec::Vec<crate::types::TableConditionalFormattingOption>>,
}
impl TableConditionalFormattingBuilder {
    /// Appends an item to `conditional_formatting_options`.
    ///
    /// To override the contents of this collection use [`set_conditional_formatting_options`](Self::set_conditional_formatting_options).
    ///
    /// <p>Conditional formatting options for a <code>PivotTableVisual</code>.</p>
    pub fn conditional_formatting_options(mut self, input: crate::types::TableConditionalFormattingOption) -> Self {
        let mut v = self.conditional_formatting_options.unwrap_or_default();
        v.push(input);
        self.conditional_formatting_options = ::std::option::Option::Some(v);
        self
    }
    /// <p>Conditional formatting options for a <code>PivotTableVisual</code>.</p>
    pub fn set_conditional_formatting_options(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::TableConditionalFormattingOption>>,
    ) -> Self {
        self.conditional_formatting_options = input;
        self
    }
    /// <p>Conditional formatting options for a <code>PivotTableVisual</code>.</p>
    pub fn get_conditional_formatting_options(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TableConditionalFormattingOption>> {
        &self.conditional_formatting_options
    }
    /// Consumes the builder and constructs a [`TableConditionalFormatting`](crate::types::TableConditionalFormatting).
    pub fn build(self) -> crate::types::TableConditionalFormatting {
        crate::types::TableConditionalFormatting {
            conditional_formatting_options: self.conditional_formatting_options,
        }
    }
}
