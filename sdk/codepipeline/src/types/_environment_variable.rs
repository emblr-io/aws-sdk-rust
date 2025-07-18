// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The environment variables for the action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnvironmentVariable {
    /// <p>The environment variable name in the key-value pair.</p>
    pub name: ::std::string::String,
    /// <p>The environment variable value in the key-value pair.</p>
    pub value: ::std::string::String,
    /// <p>Specifies the type of use for the environment variable value. The value can be either <code>PLAINTEXT</code> or <code>SECRETS_MANAGER</code>. If the value is <code>SECRETS_MANAGER</code>, provide the Secrets reference in the EnvironmentVariable value.</p>
    pub r#type: ::std::option::Option<crate::types::EnvironmentVariableType>,
}
impl EnvironmentVariable {
    /// <p>The environment variable name in the key-value pair.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The environment variable value in the key-value pair.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
    /// <p>Specifies the type of use for the environment variable value. The value can be either <code>PLAINTEXT</code> or <code>SECRETS_MANAGER</code>. If the value is <code>SECRETS_MANAGER</code>, provide the Secrets reference in the EnvironmentVariable value.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::EnvironmentVariableType> {
        self.r#type.as_ref()
    }
}
impl EnvironmentVariable {
    /// Creates a new builder-style object to manufacture [`EnvironmentVariable`](crate::types::EnvironmentVariable).
    pub fn builder() -> crate::types::builders::EnvironmentVariableBuilder {
        crate::types::builders::EnvironmentVariableBuilder::default()
    }
}

/// A builder for [`EnvironmentVariable`](crate::types::EnvironmentVariable).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnvironmentVariableBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::EnvironmentVariableType>,
}
impl EnvironmentVariableBuilder {
    /// <p>The environment variable name in the key-value pair.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The environment variable name in the key-value pair.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The environment variable name in the key-value pair.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The environment variable value in the key-value pair.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The environment variable value in the key-value pair.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The environment variable value in the key-value pair.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>Specifies the type of use for the environment variable value. The value can be either <code>PLAINTEXT</code> or <code>SECRETS_MANAGER</code>. If the value is <code>SECRETS_MANAGER</code>, provide the Secrets reference in the EnvironmentVariable value.</p>
    pub fn r#type(mut self, input: crate::types::EnvironmentVariableType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the type of use for the environment variable value. The value can be either <code>PLAINTEXT</code> or <code>SECRETS_MANAGER</code>. If the value is <code>SECRETS_MANAGER</code>, provide the Secrets reference in the EnvironmentVariable value.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::EnvironmentVariableType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Specifies the type of use for the environment variable value. The value can be either <code>PLAINTEXT</code> or <code>SECRETS_MANAGER</code>. If the value is <code>SECRETS_MANAGER</code>, provide the Secrets reference in the EnvironmentVariable value.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::EnvironmentVariableType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`EnvironmentVariable`](crate::types::EnvironmentVariable).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::EnvironmentVariableBuilder::name)
    /// - [`value`](crate::types::builders::EnvironmentVariableBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::EnvironmentVariable, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EnvironmentVariable {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building EnvironmentVariable",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building EnvironmentVariable",
                )
            })?,
            r#type: self.r#type,
        })
    }
}
