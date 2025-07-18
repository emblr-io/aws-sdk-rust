// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration information to connect to Amazon S3 as your data source.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct S3DataSourceConfiguration {
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that contains your data.</p>
    pub bucket_arn: ::std::string::String,
    /// <p>A list of S3 prefixes to include certain files or content. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html">Organizing objects using prefixes</a>.</p>
    pub inclusion_prefixes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The account ID for the owner of the S3 bucket.</p>
    pub bucket_owner_account_id: ::std::option::Option<::std::string::String>,
}
impl S3DataSourceConfiguration {
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that contains your data.</p>
    pub fn bucket_arn(&self) -> &str {
        use std::ops::Deref;
        self.bucket_arn.deref()
    }
    /// <p>A list of S3 prefixes to include certain files or content. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html">Organizing objects using prefixes</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.inclusion_prefixes.is_none()`.
    pub fn inclusion_prefixes(&self) -> &[::std::string::String] {
        self.inclusion_prefixes.as_deref().unwrap_or_default()
    }
    /// <p>The account ID for the owner of the S3 bucket.</p>
    pub fn bucket_owner_account_id(&self) -> ::std::option::Option<&str> {
        self.bucket_owner_account_id.as_deref()
    }
}
impl S3DataSourceConfiguration {
    /// Creates a new builder-style object to manufacture [`S3DataSourceConfiguration`](crate::types::S3DataSourceConfiguration).
    pub fn builder() -> crate::types::builders::S3DataSourceConfigurationBuilder {
        crate::types::builders::S3DataSourceConfigurationBuilder::default()
    }
}

/// A builder for [`S3DataSourceConfiguration`](crate::types::S3DataSourceConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct S3DataSourceConfigurationBuilder {
    pub(crate) bucket_arn: ::std::option::Option<::std::string::String>,
    pub(crate) inclusion_prefixes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) bucket_owner_account_id: ::std::option::Option<::std::string::String>,
}
impl S3DataSourceConfigurationBuilder {
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that contains your data.</p>
    /// This field is required.
    pub fn bucket_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that contains your data.</p>
    pub fn set_bucket_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the S3 bucket that contains your data.</p>
    pub fn get_bucket_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_arn
    }
    /// Appends an item to `inclusion_prefixes`.
    ///
    /// To override the contents of this collection use [`set_inclusion_prefixes`](Self::set_inclusion_prefixes).
    ///
    /// <p>A list of S3 prefixes to include certain files or content. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html">Organizing objects using prefixes</a>.</p>
    pub fn inclusion_prefixes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.inclusion_prefixes.unwrap_or_default();
        v.push(input.into());
        self.inclusion_prefixes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of S3 prefixes to include certain files or content. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html">Organizing objects using prefixes</a>.</p>
    pub fn set_inclusion_prefixes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.inclusion_prefixes = input;
        self
    }
    /// <p>A list of S3 prefixes to include certain files or content. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-prefixes.html">Organizing objects using prefixes</a>.</p>
    pub fn get_inclusion_prefixes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.inclusion_prefixes
    }
    /// <p>The account ID for the owner of the S3 bucket.</p>
    pub fn bucket_owner_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_owner_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID for the owner of the S3 bucket.</p>
    pub fn set_bucket_owner_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_owner_account_id = input;
        self
    }
    /// <p>The account ID for the owner of the S3 bucket.</p>
    pub fn get_bucket_owner_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_owner_account_id
    }
    /// Consumes the builder and constructs a [`S3DataSourceConfiguration`](crate::types::S3DataSourceConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`bucket_arn`](crate::types::builders::S3DataSourceConfigurationBuilder::bucket_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::S3DataSourceConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::S3DataSourceConfiguration {
            bucket_arn: self.bucket_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "bucket_arn",
                    "bucket_arn was not specified but it is required when building S3DataSourceConfiguration",
                )
            })?,
            inclusion_prefixes: self.inclusion_prefixes,
            bucket_owner_account_id: self.bucket_owner_account_id,
        })
    }
}
