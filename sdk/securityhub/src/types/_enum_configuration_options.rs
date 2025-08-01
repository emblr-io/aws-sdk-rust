// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The options for customizing a security control parameter that is an enum.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnumConfigurationOptions {
    /// <p>The Security Hub default value for a control parameter that is an enum.</p>
    pub default_value: ::std::option::Option<::std::string::String>,
    /// <p>The valid values for a control parameter that is an enum.</p>
    pub allowed_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl EnumConfigurationOptions {
    /// <p>The Security Hub default value for a control parameter that is an enum.</p>
    pub fn default_value(&self) -> ::std::option::Option<&str> {
        self.default_value.as_deref()
    }
    /// <p>The valid values for a control parameter that is an enum.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.allowed_values.is_none()`.
    pub fn allowed_values(&self) -> &[::std::string::String] {
        self.allowed_values.as_deref().unwrap_or_default()
    }
}
impl EnumConfigurationOptions {
    /// Creates a new builder-style object to manufacture [`EnumConfigurationOptions`](crate::types::EnumConfigurationOptions).
    pub fn builder() -> crate::types::builders::EnumConfigurationOptionsBuilder {
        crate::types::builders::EnumConfigurationOptionsBuilder::default()
    }
}

/// A builder for [`EnumConfigurationOptions`](crate::types::EnumConfigurationOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnumConfigurationOptionsBuilder {
    pub(crate) default_value: ::std::option::Option<::std::string::String>,
    pub(crate) allowed_values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl EnumConfigurationOptionsBuilder {
    /// <p>The Security Hub default value for a control parameter that is an enum.</p>
    pub fn default_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Security Hub default value for a control parameter that is an enum.</p>
    pub fn set_default_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_value = input;
        self
    }
    /// <p>The Security Hub default value for a control parameter that is an enum.</p>
    pub fn get_default_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_value
    }
    /// Appends an item to `allowed_values`.
    ///
    /// To override the contents of this collection use [`set_allowed_values`](Self::set_allowed_values).
    ///
    /// <p>The valid values for a control parameter that is an enum.</p>
    pub fn allowed_values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.allowed_values.unwrap_or_default();
        v.push(input.into());
        self.allowed_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The valid values for a control parameter that is an enum.</p>
    pub fn set_allowed_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.allowed_values = input;
        self
    }
    /// <p>The valid values for a control parameter that is an enum.</p>
    pub fn get_allowed_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.allowed_values
    }
    /// Consumes the builder and constructs a [`EnumConfigurationOptions`](crate::types::EnumConfigurationOptions).
    pub fn build(self) -> crate::types::EnumConfigurationOptions {
        crate::types::EnumConfigurationOptions {
            default_value: self.default_value,
            allowed_values: self.allowed_values,
        }
    }
}
