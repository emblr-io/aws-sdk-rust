// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the configurable settings for a directory.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Setting {
    /// <p>The name of the directory setting. For example:</p>
    /// <p><code>TLS_1_0</code></p>
    pub name: ::std::string::String,
    /// <p>The value of the directory setting for which to retrieve information. For example, for <code>TLS_1_0</code>, the valid values are: <code>Enable</code> and <code>Disable</code>.</p>
    pub value: ::std::string::String,
}
impl Setting {
    /// <p>The name of the directory setting. For example:</p>
    /// <p><code>TLS_1_0</code></p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The value of the directory setting for which to retrieve information. For example, for <code>TLS_1_0</code>, the valid values are: <code>Enable</code> and <code>Disable</code>.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl Setting {
    /// Creates a new builder-style object to manufacture [`Setting`](crate::types::Setting).
    pub fn builder() -> crate::types::builders::SettingBuilder {
        crate::types::builders::SettingBuilder::default()
    }
}

/// A builder for [`Setting`](crate::types::Setting).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SettingBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl SettingBuilder {
    /// <p>The name of the directory setting. For example:</p>
    /// <p><code>TLS_1_0</code></p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the directory setting. For example:</p>
    /// <p><code>TLS_1_0</code></p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the directory setting. For example:</p>
    /// <p><code>TLS_1_0</code></p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The value of the directory setting for which to retrieve information. For example, for <code>TLS_1_0</code>, the valid values are: <code>Enable</code> and <code>Disable</code>.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the directory setting for which to retrieve information. For example, for <code>TLS_1_0</code>, the valid values are: <code>Enable</code> and <code>Disable</code>.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the directory setting for which to retrieve information. For example, for <code>TLS_1_0</code>, the valid values are: <code>Enable</code> and <code>Disable</code>.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`Setting`](crate::types::Setting).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::SettingBuilder::name)
    /// - [`value`](crate::types::builders::SettingBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::Setting, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Setting {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building Setting",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building Setting",
                )
            })?,
        })
    }
}
