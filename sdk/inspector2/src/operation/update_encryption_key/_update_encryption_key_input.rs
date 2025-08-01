// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateEncryptionKeyInput {
    /// <p>A KMS key ID for the encryption key.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The scan type for the encryption key.</p>
    pub scan_type: ::std::option::Option<crate::types::ScanType>,
    /// <p>The resource type for the encryption key.</p>
    pub resource_type: ::std::option::Option<crate::types::ResourceType>,
}
impl UpdateEncryptionKeyInput {
    /// <p>A KMS key ID for the encryption key.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>The scan type for the encryption key.</p>
    pub fn scan_type(&self) -> ::std::option::Option<&crate::types::ScanType> {
        self.scan_type.as_ref()
    }
    /// <p>The resource type for the encryption key.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::ResourceType> {
        self.resource_type.as_ref()
    }
}
impl UpdateEncryptionKeyInput {
    /// Creates a new builder-style object to manufacture [`UpdateEncryptionKeyInput`](crate::operation::update_encryption_key::UpdateEncryptionKeyInput).
    pub fn builder() -> crate::operation::update_encryption_key::builders::UpdateEncryptionKeyInputBuilder {
        crate::operation::update_encryption_key::builders::UpdateEncryptionKeyInputBuilder::default()
    }
}

/// A builder for [`UpdateEncryptionKeyInput`](crate::operation::update_encryption_key::UpdateEncryptionKeyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateEncryptionKeyInputBuilder {
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) scan_type: ::std::option::Option<crate::types::ScanType>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ResourceType>,
}
impl UpdateEncryptionKeyInputBuilder {
    /// <p>A KMS key ID for the encryption key.</p>
    /// This field is required.
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A KMS key ID for the encryption key.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>A KMS key ID for the encryption key.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>The scan type for the encryption key.</p>
    /// This field is required.
    pub fn scan_type(mut self, input: crate::types::ScanType) -> Self {
        self.scan_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The scan type for the encryption key.</p>
    pub fn set_scan_type(mut self, input: ::std::option::Option<crate::types::ScanType>) -> Self {
        self.scan_type = input;
        self
    }
    /// <p>The scan type for the encryption key.</p>
    pub fn get_scan_type(&self) -> &::std::option::Option<crate::types::ScanType> {
        &self.scan_type
    }
    /// <p>The resource type for the encryption key.</p>
    /// This field is required.
    pub fn resource_type(mut self, input: crate::types::ResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource type for the encryption key.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The resource type for the encryption key.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.resource_type
    }
    /// Consumes the builder and constructs a [`UpdateEncryptionKeyInput`](crate::operation::update_encryption_key::UpdateEncryptionKeyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_encryption_key::UpdateEncryptionKeyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_encryption_key::UpdateEncryptionKeyInput {
            kms_key_id: self.kms_key_id,
            scan_type: self.scan_type,
            resource_type: self.resource_type,
        })
    }
}
