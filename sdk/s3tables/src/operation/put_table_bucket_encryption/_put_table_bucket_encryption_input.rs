// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutTableBucketEncryptionInput {
    /// <p>The Amazon Resource Name (ARN) of the table bucket.</p>
    pub table_bucket_arn: ::std::option::Option<::std::string::String>,
    /// <p>The encryption configuration to apply to the table bucket.</p>
    pub encryption_configuration: ::std::option::Option<crate::types::EncryptionConfiguration>,
}
impl PutTableBucketEncryptionInput {
    /// <p>The Amazon Resource Name (ARN) of the table bucket.</p>
    pub fn table_bucket_arn(&self) -> ::std::option::Option<&str> {
        self.table_bucket_arn.as_deref()
    }
    /// <p>The encryption configuration to apply to the table bucket.</p>
    pub fn encryption_configuration(&self) -> ::std::option::Option<&crate::types::EncryptionConfiguration> {
        self.encryption_configuration.as_ref()
    }
}
impl PutTableBucketEncryptionInput {
    /// Creates a new builder-style object to manufacture [`PutTableBucketEncryptionInput`](crate::operation::put_table_bucket_encryption::PutTableBucketEncryptionInput).
    pub fn builder() -> crate::operation::put_table_bucket_encryption::builders::PutTableBucketEncryptionInputBuilder {
        crate::operation::put_table_bucket_encryption::builders::PutTableBucketEncryptionInputBuilder::default()
    }
}

/// A builder for [`PutTableBucketEncryptionInput`](crate::operation::put_table_bucket_encryption::PutTableBucketEncryptionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutTableBucketEncryptionInputBuilder {
    pub(crate) table_bucket_arn: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_configuration: ::std::option::Option<crate::types::EncryptionConfiguration>,
}
impl PutTableBucketEncryptionInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the table bucket.</p>
    /// This field is required.
    pub fn table_bucket_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_bucket_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table bucket.</p>
    pub fn set_table_bucket_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_bucket_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the table bucket.</p>
    pub fn get_table_bucket_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_bucket_arn
    }
    /// <p>The encryption configuration to apply to the table bucket.</p>
    /// This field is required.
    pub fn encryption_configuration(mut self, input: crate::types::EncryptionConfiguration) -> Self {
        self.encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption configuration to apply to the table bucket.</p>
    pub fn set_encryption_configuration(mut self, input: ::std::option::Option<crate::types::EncryptionConfiguration>) -> Self {
        self.encryption_configuration = input;
        self
    }
    /// <p>The encryption configuration to apply to the table bucket.</p>
    pub fn get_encryption_configuration(&self) -> &::std::option::Option<crate::types::EncryptionConfiguration> {
        &self.encryption_configuration
    }
    /// Consumes the builder and constructs a [`PutTableBucketEncryptionInput`](crate::operation::put_table_bucket_encryption::PutTableBucketEncryptionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_table_bucket_encryption::PutTableBucketEncryptionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::put_table_bucket_encryption::PutTableBucketEncryptionInput {
            table_bucket_arn: self.table_bucket_arn,
            encryption_configuration: self.encryption_configuration,
        })
    }
}
