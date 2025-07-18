// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Source details for an Amazon S3 data access asset.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3DataAccessAssetSourceEntry {
    /// <p>The Amazon S3 bucket used for hosting shared data in the Amazon S3 data access.</p>
    pub bucket: ::std::string::String,
    /// <p>Organizes Amazon S3 asset key prefixes stored in an Amazon S3 bucket.</p>
    pub key_prefixes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The keys used to create the Amazon S3 data access.</p>
    pub keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>List of AWS KMS CMKs (Key Management System Customer Managed Keys) and ARNs used to encrypt S3 objects being shared in this S3 Data Access asset.</p>
    pub kms_keys_to_grant: ::std::option::Option<::std::vec::Vec<crate::types::KmsKeyToGrant>>,
}
impl S3DataAccessAssetSourceEntry {
    /// <p>The Amazon S3 bucket used for hosting shared data in the Amazon S3 data access.</p>
    pub fn bucket(&self) -> &str {
        use std::ops::Deref;
        self.bucket.deref()
    }
    /// <p>Organizes Amazon S3 asset key prefixes stored in an Amazon S3 bucket.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.key_prefixes.is_none()`.
    pub fn key_prefixes(&self) -> &[::std::string::String] {
        self.key_prefixes.as_deref().unwrap_or_default()
    }
    /// <p>The keys used to create the Amazon S3 data access.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.keys.is_none()`.
    pub fn keys(&self) -> &[::std::string::String] {
        self.keys.as_deref().unwrap_or_default()
    }
    /// <p>List of AWS KMS CMKs (Key Management System Customer Managed Keys) and ARNs used to encrypt S3 objects being shared in this S3 Data Access asset.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.kms_keys_to_grant.is_none()`.
    pub fn kms_keys_to_grant(&self) -> &[crate::types::KmsKeyToGrant] {
        self.kms_keys_to_grant.as_deref().unwrap_or_default()
    }
}
impl S3DataAccessAssetSourceEntry {
    /// Creates a new builder-style object to manufacture [`S3DataAccessAssetSourceEntry`](crate::types::S3DataAccessAssetSourceEntry).
    pub fn builder() -> crate::types::builders::S3DataAccessAssetSourceEntryBuilder {
        crate::types::builders::S3DataAccessAssetSourceEntryBuilder::default()
    }
}

/// A builder for [`S3DataAccessAssetSourceEntry`](crate::types::S3DataAccessAssetSourceEntry).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3DataAccessAssetSourceEntryBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) key_prefixes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) keys: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) kms_keys_to_grant: ::std::option::Option<::std::vec::Vec<crate::types::KmsKeyToGrant>>,
}
impl S3DataAccessAssetSourceEntryBuilder {
    /// <p>The Amazon S3 bucket used for hosting shared data in the Amazon S3 data access.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 bucket used for hosting shared data in the Amazon S3 data access.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The Amazon S3 bucket used for hosting shared data in the Amazon S3 data access.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// Appends an item to `key_prefixes`.
    ///
    /// To override the contents of this collection use [`set_key_prefixes`](Self::set_key_prefixes).
    ///
    /// <p>Organizes Amazon S3 asset key prefixes stored in an Amazon S3 bucket.</p>
    pub fn key_prefixes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.key_prefixes.unwrap_or_default();
        v.push(input.into());
        self.key_prefixes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Organizes Amazon S3 asset key prefixes stored in an Amazon S3 bucket.</p>
    pub fn set_key_prefixes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.key_prefixes = input;
        self
    }
    /// <p>Organizes Amazon S3 asset key prefixes stored in an Amazon S3 bucket.</p>
    pub fn get_key_prefixes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.key_prefixes
    }
    /// Appends an item to `keys`.
    ///
    /// To override the contents of this collection use [`set_keys`](Self::set_keys).
    ///
    /// <p>The keys used to create the Amazon S3 data access.</p>
    pub fn keys(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.keys.unwrap_or_default();
        v.push(input.into());
        self.keys = ::std::option::Option::Some(v);
        self
    }
    /// <p>The keys used to create the Amazon S3 data access.</p>
    pub fn set_keys(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.keys = input;
        self
    }
    /// <p>The keys used to create the Amazon S3 data access.</p>
    pub fn get_keys(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.keys
    }
    /// Appends an item to `kms_keys_to_grant`.
    ///
    /// To override the contents of this collection use [`set_kms_keys_to_grant`](Self::set_kms_keys_to_grant).
    ///
    /// <p>List of AWS KMS CMKs (Key Management System Customer Managed Keys) and ARNs used to encrypt S3 objects being shared in this S3 Data Access asset.</p>
    pub fn kms_keys_to_grant(mut self, input: crate::types::KmsKeyToGrant) -> Self {
        let mut v = self.kms_keys_to_grant.unwrap_or_default();
        v.push(input);
        self.kms_keys_to_grant = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of AWS KMS CMKs (Key Management System Customer Managed Keys) and ARNs used to encrypt S3 objects being shared in this S3 Data Access asset.</p>
    pub fn set_kms_keys_to_grant(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::KmsKeyToGrant>>) -> Self {
        self.kms_keys_to_grant = input;
        self
    }
    /// <p>List of AWS KMS CMKs (Key Management System Customer Managed Keys) and ARNs used to encrypt S3 objects being shared in this S3 Data Access asset.</p>
    pub fn get_kms_keys_to_grant(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::KmsKeyToGrant>> {
        &self.kms_keys_to_grant
    }
    /// Consumes the builder and constructs a [`S3DataAccessAssetSourceEntry`](crate::types::S3DataAccessAssetSourceEntry).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket`](crate::types::builders::S3DataAccessAssetSourceEntryBuilder::bucket)
    pub fn build(self) -> ::std::result::Result<crate::types::S3DataAccessAssetSourceEntry, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3DataAccessAssetSourceEntry {
            bucket: self.bucket.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket",
                    "bucket was not specified but it is required when building S3DataAccessAssetSourceEntry",
                )
            })?,
            key_prefixes: self.key_prefixes,
            keys: self.keys,
            kms_keys_to_grant: self.kms_keys_to_grant,
        })
    }
}
