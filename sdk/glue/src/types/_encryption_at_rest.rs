// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the encryption-at-rest configuration for the Data Catalog.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EncryptionAtRest {
    /// <p>The encryption-at-rest mode for encrypting Data Catalog data.</p>
    pub catalog_encryption_mode: crate::types::CatalogEncryptionMode,
    /// <p>The ID of the KMS key to use for encryption at rest.</p>
    pub sse_aws_kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The role that Glue assumes to encrypt and decrypt the Data Catalog objects on the caller's behalf.</p>
    pub catalog_encryption_service_role: ::std::option::Option<::std::string::String>,
}
impl EncryptionAtRest {
    /// <p>The encryption-at-rest mode for encrypting Data Catalog data.</p>
    pub fn catalog_encryption_mode(&self) -> &crate::types::CatalogEncryptionMode {
        &self.catalog_encryption_mode
    }
    /// <p>The ID of the KMS key to use for encryption at rest.</p>
    pub fn sse_aws_kms_key_id(&self) -> ::std::option::Option<&str> {
        self.sse_aws_kms_key_id.as_deref()
    }
    /// <p>The role that Glue assumes to encrypt and decrypt the Data Catalog objects on the caller's behalf.</p>
    pub fn catalog_encryption_service_role(&self) -> ::std::option::Option<&str> {
        self.catalog_encryption_service_role.as_deref()
    }
}
impl EncryptionAtRest {
    /// Creates a new builder-style object to manufacture [`EncryptionAtRest`](crate::types::EncryptionAtRest).
    pub fn builder() -> crate::types::builders::EncryptionAtRestBuilder {
        crate::types::builders::EncryptionAtRestBuilder::default()
    }
}

/// A builder for [`EncryptionAtRest`](crate::types::EncryptionAtRest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EncryptionAtRestBuilder {
    pub(crate) catalog_encryption_mode: ::std::option::Option<crate::types::CatalogEncryptionMode>,
    pub(crate) sse_aws_kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) catalog_encryption_service_role: ::std::option::Option<::std::string::String>,
}
impl EncryptionAtRestBuilder {
    /// <p>The encryption-at-rest mode for encrypting Data Catalog data.</p>
    /// This field is required.
    pub fn catalog_encryption_mode(mut self, input: crate::types::CatalogEncryptionMode) -> Self {
        self.catalog_encryption_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption-at-rest mode for encrypting Data Catalog data.</p>
    pub fn set_catalog_encryption_mode(mut self, input: ::std::option::Option<crate::types::CatalogEncryptionMode>) -> Self {
        self.catalog_encryption_mode = input;
        self
    }
    /// <p>The encryption-at-rest mode for encrypting Data Catalog data.</p>
    pub fn get_catalog_encryption_mode(&self) -> &::std::option::Option<crate::types::CatalogEncryptionMode> {
        &self.catalog_encryption_mode
    }
    /// <p>The ID of the KMS key to use for encryption at rest.</p>
    pub fn sse_aws_kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sse_aws_kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the KMS key to use for encryption at rest.</p>
    pub fn set_sse_aws_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sse_aws_kms_key_id = input;
        self
    }
    /// <p>The ID of the KMS key to use for encryption at rest.</p>
    pub fn get_sse_aws_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.sse_aws_kms_key_id
    }
    /// <p>The role that Glue assumes to encrypt and decrypt the Data Catalog objects on the caller's behalf.</p>
    pub fn catalog_encryption_service_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_encryption_service_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The role that Glue assumes to encrypt and decrypt the Data Catalog objects on the caller's behalf.</p>
    pub fn set_catalog_encryption_service_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_encryption_service_role = input;
        self
    }
    /// <p>The role that Glue assumes to encrypt and decrypt the Data Catalog objects on the caller's behalf.</p>
    pub fn get_catalog_encryption_service_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_encryption_service_role
    }
    /// Consumes the builder and constructs a [`EncryptionAtRest`](crate::types::EncryptionAtRest).
    /// This method will fail if any of the following fields are not set:
    /// - [`catalog_encryption_mode`](crate::types::builders::EncryptionAtRestBuilder::catalog_encryption_mode)
    pub fn build(self) -> ::std::result::Result<crate::types::EncryptionAtRest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EncryptionAtRest {
            catalog_encryption_mode: self.catalog_encryption_mode.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "catalog_encryption_mode",
                    "catalog_encryption_mode was not specified but it is required when building EncryptionAtRest",
                )
            })?,
            sse_aws_kms_key_id: self.sse_aws_kms_key_id,
            catalog_encryption_service_role: self.catalog_encryption_service_role,
        })
    }
}
