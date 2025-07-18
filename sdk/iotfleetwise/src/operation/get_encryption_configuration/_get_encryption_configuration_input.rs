// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetEncryptionConfigurationInput {}
impl GetEncryptionConfigurationInput {
    /// Creates a new builder-style object to manufacture [`GetEncryptionConfigurationInput`](crate::operation::get_encryption_configuration::GetEncryptionConfigurationInput).
    pub fn builder() -> crate::operation::get_encryption_configuration::builders::GetEncryptionConfigurationInputBuilder {
        crate::operation::get_encryption_configuration::builders::GetEncryptionConfigurationInputBuilder::default()
    }
}

/// A builder for [`GetEncryptionConfigurationInput`](crate::operation::get_encryption_configuration::GetEncryptionConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetEncryptionConfigurationInputBuilder {}
impl GetEncryptionConfigurationInputBuilder {
    /// Consumes the builder and constructs a [`GetEncryptionConfigurationInput`](crate::operation::get_encryption_configuration::GetEncryptionConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_encryption_configuration::GetEncryptionConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_encryption_configuration::GetEncryptionConfigurationInput {})
    }
}
