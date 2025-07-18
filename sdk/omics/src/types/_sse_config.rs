// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Server-side encryption (SSE) settings for a store.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SseConfig {
    /// <p>The encryption type.</p>
    pub r#type: crate::types::EncryptionType,
    /// <p>An encryption key ARN.</p>
    pub key_arn: ::std::option::Option<::std::string::String>,
}
impl SseConfig {
    /// <p>The encryption type.</p>
    pub fn r#type(&self) -> &crate::types::EncryptionType {
        &self.r#type
    }
    /// <p>An encryption key ARN.</p>
    pub fn key_arn(&self) -> ::std::option::Option<&str> {
        self.key_arn.as_deref()
    }
}
impl SseConfig {
    /// Creates a new builder-style object to manufacture [`SseConfig`](crate::types::SseConfig).
    pub fn builder() -> crate::types::builders::SseConfigBuilder {
        crate::types::builders::SseConfigBuilder::default()
    }
}

/// A builder for [`SseConfig`](crate::types::SseConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SseConfigBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::EncryptionType>,
    pub(crate) key_arn: ::std::option::Option<::std::string::String>,
}
impl SseConfigBuilder {
    /// <p>The encryption type.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::EncryptionType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::EncryptionType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The encryption type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::EncryptionType> {
        &self.r#type
    }
    /// <p>An encryption key ARN.</p>
    pub fn key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An encryption key ARN.</p>
    pub fn set_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_arn = input;
        self
    }
    /// <p>An encryption key ARN.</p>
    pub fn get_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_arn
    }
    /// Consumes the builder and constructs a [`SseConfig`](crate::types::SseConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::SseConfigBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::SseConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SseConfig {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building SseConfig",
                )
            })?,
            key_arn: self.key_arn,
        })
    }
}
