// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Validation rules for a select field.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SelectValidation {
    /// <p>The minimum number of choices for the select.</p>
    pub min_choices: i32,
    /// <p>The maximum number of choices for the select.</p>
    pub max_choices: i32,
    /// <p>An array of strings for the possible selection options.</p>
    pub options: ::std::vec::Vec<::std::string::String>,
}
impl SelectValidation {
    /// <p>The minimum number of choices for the select.</p>
    pub fn min_choices(&self) -> i32 {
        self.min_choices
    }
    /// <p>The maximum number of choices for the select.</p>
    pub fn max_choices(&self) -> i32 {
        self.max_choices
    }
    /// <p>An array of strings for the possible selection options.</p>
    pub fn options(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.options.deref()
    }
}
impl SelectValidation {
    /// Creates a new builder-style object to manufacture [`SelectValidation`](crate::types::SelectValidation).
    pub fn builder() -> crate::types::builders::SelectValidationBuilder {
        crate::types::builders::SelectValidationBuilder::default()
    }
}

/// A builder for [`SelectValidation`](crate::types::SelectValidation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SelectValidationBuilder {
    pub(crate) min_choices: ::std::option::Option<i32>,
    pub(crate) max_choices: ::std::option::Option<i32>,
    pub(crate) options: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl SelectValidationBuilder {
    /// <p>The minimum number of choices for the select.</p>
    /// This field is required.
    pub fn min_choices(mut self, input: i32) -> Self {
        self.min_choices = ::std::option::Option::Some(input);
        self
    }
    /// <p>The minimum number of choices for the select.</p>
    pub fn set_min_choices(mut self, input: ::std::option::Option<i32>) -> Self {
        self.min_choices = input;
        self
    }
    /// <p>The minimum number of choices for the select.</p>
    pub fn get_min_choices(&self) -> &::std::option::Option<i32> {
        &self.min_choices
    }
    /// <p>The maximum number of choices for the select.</p>
    /// This field is required.
    pub fn max_choices(mut self, input: i32) -> Self {
        self.max_choices = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of choices for the select.</p>
    pub fn set_max_choices(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_choices = input;
        self
    }
    /// <p>The maximum number of choices for the select.</p>
    pub fn get_max_choices(&self) -> &::std::option::Option<i32> {
        &self.max_choices
    }
    /// Appends an item to `options`.
    ///
    /// To override the contents of this collection use [`set_options`](Self::set_options).
    ///
    /// <p>An array of strings for the possible selection options.</p>
    pub fn options(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.options.unwrap_or_default();
        v.push(input.into());
        self.options = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of strings for the possible selection options.</p>
    pub fn set_options(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.options = input;
        self
    }
    /// <p>An array of strings for the possible selection options.</p>
    pub fn get_options(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.options
    }
    /// Consumes the builder and constructs a [`SelectValidation`](crate::types::SelectValidation).
    /// This method will fail if any of the following fields are not set:
    /// - [`min_choices`](crate::types::builders::SelectValidationBuilder::min_choices)
    /// - [`max_choices`](crate::types::builders::SelectValidationBuilder::max_choices)
    /// - [`options`](crate::types::builders::SelectValidationBuilder::options)
    pub fn build(self) -> ::std::result::Result<crate::types::SelectValidation, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SelectValidation {
            min_choices: self.min_choices.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "min_choices",
                    "min_choices was not specified but it is required when building SelectValidation",
                )
            })?,
            max_choices: self.max_choices.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_choices",
                    "max_choices was not specified but it is required when building SelectValidation",
                )
            })?,
            options: self.options.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "options",
                    "options was not specified but it is required when building SelectValidation",
                )
            })?,
        })
    }
}
