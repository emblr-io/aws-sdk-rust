// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A complex data type that includes the profile configurations and other options specified for field-level encryption.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FieldLevelEncryption {
    /// <p>The configuration ID for a field-level encryption configuration which includes a set of profiles that specify certain selected data fields to be encrypted by specific public keys.</p>
    pub id: ::std::string::String,
    /// <p>The last time the field-level encryption configuration was changed.</p>
    pub last_modified_time: ::aws_smithy_types::DateTime,
    /// <p>A complex data type that includes the profile configurations specified for field-level encryption.</p>
    pub field_level_encryption_config: ::std::option::Option<crate::types::FieldLevelEncryptionConfig>,
}
impl FieldLevelEncryption {
    /// <p>The configuration ID for a field-level encryption configuration which includes a set of profiles that specify certain selected data fields to be encrypted by specific public keys.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The last time the field-level encryption configuration was changed.</p>
    pub fn last_modified_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_modified_time
    }
    /// <p>A complex data type that includes the profile configurations specified for field-level encryption.</p>
    pub fn field_level_encryption_config(&self) -> ::std::option::Option<&crate::types::FieldLevelEncryptionConfig> {
        self.field_level_encryption_config.as_ref()
    }
}
impl FieldLevelEncryption {
    /// Creates a new builder-style object to manufacture [`FieldLevelEncryption`](crate::types::FieldLevelEncryption).
    pub fn builder() -> crate::types::builders::FieldLevelEncryptionBuilder {
        crate::types::builders::FieldLevelEncryptionBuilder::default()
    }
}

/// A builder for [`FieldLevelEncryption`](crate::types::FieldLevelEncryption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FieldLevelEncryptionBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) last_modified_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) field_level_encryption_config: ::std::option::Option<crate::types::FieldLevelEncryptionConfig>,
}
impl FieldLevelEncryptionBuilder {
    /// <p>The configuration ID for a field-level encryption configuration which includes a set of profiles that specify certain selected data fields to be encrypted by specific public keys.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The configuration ID for a field-level encryption configuration which includes a set of profiles that specify certain selected data fields to be encrypted by specific public keys.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The configuration ID for a field-level encryption configuration which includes a set of profiles that specify certain selected data fields to be encrypted by specific public keys.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The last time the field-level encryption configuration was changed.</p>
    /// This field is required.
    pub fn last_modified_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The last time the field-level encryption configuration was changed.</p>
    pub fn set_last_modified_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified_time = input;
        self
    }
    /// <p>The last time the field-level encryption configuration was changed.</p>
    pub fn get_last_modified_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified_time
    }
    /// <p>A complex data type that includes the profile configurations specified for field-level encryption.</p>
    /// This field is required.
    pub fn field_level_encryption_config(mut self, input: crate::types::FieldLevelEncryptionConfig) -> Self {
        self.field_level_encryption_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex data type that includes the profile configurations specified for field-level encryption.</p>
    pub fn set_field_level_encryption_config(mut self, input: ::std::option::Option<crate::types::FieldLevelEncryptionConfig>) -> Self {
        self.field_level_encryption_config = input;
        self
    }
    /// <p>A complex data type that includes the profile configurations specified for field-level encryption.</p>
    pub fn get_field_level_encryption_config(&self) -> &::std::option::Option<crate::types::FieldLevelEncryptionConfig> {
        &self.field_level_encryption_config
    }
    /// Consumes the builder and constructs a [`FieldLevelEncryption`](crate::types::FieldLevelEncryption).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::FieldLevelEncryptionBuilder::id)
    /// - [`last_modified_time`](crate::types::builders::FieldLevelEncryptionBuilder::last_modified_time)
    pub fn build(self) -> ::std::result::Result<crate::types::FieldLevelEncryption, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FieldLevelEncryption {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building FieldLevelEncryption",
                )
            })?,
            last_modified_time: self.last_modified_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified_time",
                    "last_modified_time was not specified but it is required when building FieldLevelEncryption",
                )
            })?,
            field_level_encryption_config: self.field_level_encryption_config,
        })
    }
}
