// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFieldLevelEncryptionProfileOutput {
    /// <p>Return the field-level encryption profile information.</p>
    pub field_level_encryption_profile: ::std::option::Option<crate::types::FieldLevelEncryptionProfile>,
    /// <p>The current version of the field level encryption profile. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetFieldLevelEncryptionProfileOutput {
    /// <p>Return the field-level encryption profile information.</p>
    pub fn field_level_encryption_profile(&self) -> ::std::option::Option<&crate::types::FieldLevelEncryptionProfile> {
        self.field_level_encryption_profile.as_ref()
    }
    /// <p>The current version of the field level encryption profile. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetFieldLevelEncryptionProfileOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetFieldLevelEncryptionProfileOutput {
    /// Creates a new builder-style object to manufacture [`GetFieldLevelEncryptionProfileOutput`](crate::operation::get_field_level_encryption_profile::GetFieldLevelEncryptionProfileOutput).
    pub fn builder() -> crate::operation::get_field_level_encryption_profile::builders::GetFieldLevelEncryptionProfileOutputBuilder {
        crate::operation::get_field_level_encryption_profile::builders::GetFieldLevelEncryptionProfileOutputBuilder::default()
    }
}

/// A builder for [`GetFieldLevelEncryptionProfileOutput`](crate::operation::get_field_level_encryption_profile::GetFieldLevelEncryptionProfileOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFieldLevelEncryptionProfileOutputBuilder {
    pub(crate) field_level_encryption_profile: ::std::option::Option<crate::types::FieldLevelEncryptionProfile>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetFieldLevelEncryptionProfileOutputBuilder {
    /// <p>Return the field-level encryption profile information.</p>
    pub fn field_level_encryption_profile(mut self, input: crate::types::FieldLevelEncryptionProfile) -> Self {
        self.field_level_encryption_profile = ::std::option::Option::Some(input);
        self
    }
    /// <p>Return the field-level encryption profile information.</p>
    pub fn set_field_level_encryption_profile(mut self, input: ::std::option::Option<crate::types::FieldLevelEncryptionProfile>) -> Self {
        self.field_level_encryption_profile = input;
        self
    }
    /// <p>Return the field-level encryption profile information.</p>
    pub fn get_field_level_encryption_profile(&self) -> &::std::option::Option<crate::types::FieldLevelEncryptionProfile> {
        &self.field_level_encryption_profile
    }
    /// <p>The current version of the field level encryption profile. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current version of the field level encryption profile. For example: <code>E2QWRUHAPOMQZL</code>.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The current version of the field level encryption profile. For example: <code>E2QWRUHAPOMQZL</code>.</p>
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
    /// Consumes the builder and constructs a [`GetFieldLevelEncryptionProfileOutput`](crate::operation::get_field_level_encryption_profile::GetFieldLevelEncryptionProfileOutput).
    pub fn build(self) -> crate::operation::get_field_level_encryption_profile::GetFieldLevelEncryptionProfileOutput {
        crate::operation::get_field_level_encryption_profile::GetFieldLevelEncryptionProfileOutput {
            field_level_encryption_profile: self.field_level_encryption_profile,
            e_tag: self.e_tag,
            _request_id: self._request_id,
        }
    }
}
