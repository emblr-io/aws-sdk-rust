// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filter the selection by using a condition.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Filter {
    /// <p>The key that you're filtering on.</p>
    pub key: ::std::string::String,
    /// <p>The condition accepts before or after a specified time, equal to a string, or equal to an integer.</p>
    pub condition: ::std::option::Option<crate::types::Condition>,
}
impl Filter {
    /// <p>The key that you're filtering on.</p>
    pub fn key(&self) -> &str {
        use std::ops::Deref;
        self.key.deref()
    }
    /// <p>The condition accepts before or after a specified time, equal to a string, or equal to an integer.</p>
    pub fn condition(&self) -> ::std::option::Option<&crate::types::Condition> {
        self.condition.as_ref()
    }
}
impl Filter {
    /// Creates a new builder-style object to manufacture [`Filter`](crate::types::Filter).
    pub fn builder() -> crate::types::builders::FilterBuilder {
        crate::types::builders::FilterBuilder::default()
    }
}

/// A builder for [`Filter`](crate::types::Filter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) condition: ::std::option::Option<crate::types::Condition>,
}
impl FilterBuilder {
    /// <p>The key that you're filtering on.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key that you're filtering on.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The key that you're filtering on.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>The condition accepts before or after a specified time, equal to a string, or equal to an integer.</p>
    /// This field is required.
    pub fn condition(mut self, input: crate::types::Condition) -> Self {
        self.condition = ::std::option::Option::Some(input);
        self
    }
    /// <p>The condition accepts before or after a specified time, equal to a string, or equal to an integer.</p>
    pub fn set_condition(mut self, input: ::std::option::Option<crate::types::Condition>) -> Self {
        self.condition = input;
        self
    }
    /// <p>The condition accepts before or after a specified time, equal to a string, or equal to an integer.</p>
    pub fn get_condition(&self) -> &::std::option::Option<crate::types::Condition> {
        &self.condition
    }
    /// Consumes the builder and constructs a [`Filter`](crate::types::Filter).
    /// This method will fail if any of the following fields are not set:
    /// - [`key`](crate::types::builders::FilterBuilder::key)
    pub fn build(self) -> ::std::result::Result<crate::types::Filter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Filter {
            key: self.key.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "key",
                    "key was not specified but it is required when building Filter",
                )
            })?,
            condition: self.condition,
        })
    }
}
