// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFieldLevelEncryptionProfileConfigOutput {
    /// <p>Return the field-level encryption profile configuration information.</p>
    pub field_level_encryption_profile_config: ::std::option::Option<crate::types::FieldLevelEncryptionProfileConfig>,
    /// <p>The current version of the field-level encryption profile configuration result. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetFieldLevelEncryptionProfileConfigOutput {
    /// <p>Return the field-level encryption profile configuration information.</p>
    pub fn field_level_encryption_profile_config(&self) -> ::std::option::Option<&crate::types::FieldLevelEncryptionProfileConfig> {
        self.field_level_encryption_profile_config.as_ref()
    }
    /// <p>The current version of the field-level encryption profile configuration result. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetFieldLevelEncryptionProfileConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFieldLevelEncryptionProfileConfigOutput {
    /// Creates a new builder-style object to manufacture [`GetFieldLevelEncryptionProfileConfigOutput`](crate::operation::get_field_level_encryption_profile_config::GetFieldLevelEncryptionProfileConfigOutput).
    pub fn builder() -> crate::operation::get_field_level_encryption_profile_config::builders::GetFieldLevelEncryptionProfileConfigOutputBuilder {
        crate::operation::get_field_level_encryption_profile_config::builders::GetFieldLevelEncryptionProfileConfigOutputBuilder::default()
    }
}

/// A builder for [`GetFieldLevelEncryptionProfileConfigOutput`](crate::operation::get_field_level_encryption_profile_config::GetFieldLevelEncryptionProfileConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFieldLevelEncryptionProfileConfigOutputBuilder {
    pub(crate) field_level_encryption_profile_config: ::std::option::Option<crate::types::FieldLevelEncryptionProfileConfig>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetFieldLevelEncryptionProfileConfigOutputBuilder {
    /// <p>Return the field-level encryption profile configuration information.</p>
    pub fn field_level_encryption_profile_config(mut self, input: crate::types::FieldLevelEncryptionProfileConfig) -> Self {
        self.field_level_encryption_profile_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Return the field-level encryption profile configuration information.</p>
    pub fn set_field_level_encryption_profile_config(
        mut self,
        input: ::std::option::Option<crate::types::FieldLevelEncryptionProfileConfig>,
    ) -> Self {
        self.field_level_encryption_profile_config = input;
        self
    }
    /// <p>Return the field-level encryption profile configuration information.</p>
    pub fn get_field_level_encryption_profile_config(&self) -> &::std::option::Option<crate::types::FieldLevelEncryptionProfileConfig> {
        &self.field_level_encryption_profile_config
    }
    /// <p>The current version of the field-level encryption profile configuration result. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version of the field-level encryption profile configuration result. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The current version of the field-level encryption profile configuration result. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetFieldLevelEncryptionProfileConfigOutput`](crate::operation::get_field_level_encryption_profile_config::GetFieldLevelEncryptionProfileConfigOutput).
    pub fn build(self) -> crate::operation::get_field_level_encryption_profile_config::GetFieldLevelEncryptionProfileConfigOutput {
        crate::operation::get_field_level_encryption_profile_config::GetFieldLevelEncryptionProfileConfigOutput {
            field_level_encryption_profile_config: self.field_level_encryption_profile_config,
            e_tag: self.e_tag,
            _request_id: self._request_id,
        }
    }
}
