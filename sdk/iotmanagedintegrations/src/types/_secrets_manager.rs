// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration for AWS Secrets Manager, used to securely store and manage sensitive information for connector destinations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SecretsManager {
    /// <p>The Amazon Resource Name (ARN) of the AWS Secrets Manager secret.</p>
    pub arn: ::std::string::String,
    /// <p>The version ID of the AWS Secrets Manager secret.</p>
    pub version_id: ::std::string::String,
}
impl SecretsManager {
    /// <p>The Amazon Resource Name (ARN) of the AWS Secrets Manager secret.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The version ID of the AWS Secrets Manager secret.</p>
    pub fn version_id(&self) -> &str {
        use std::ops::Deref;
        self.version_id.deref()
    }
}
impl SecretsManager {
    /// Creates a new builder-style object to manufacture [`SecretsManager`](crate::types::SecretsManager).
    pub fn builder() -> crate::types::builders::SecretsManagerBuilder {
        crate::types::builders::SecretsManagerBuilder::default()
    }
}

/// A builder for [`SecretsManager`](crate::types::SecretsManager).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SecretsManagerBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
}
impl SecretsManagerBuilder {
    /// <p>The Amazon Resource Name (ARN) of the AWS Secrets Manager secret.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS Secrets Manager secret.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the AWS Secrets Manager secret.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The version ID of the AWS Secrets Manager secret.</p>
    /// This field is required.
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version ID of the AWS Secrets Manager secret.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The version ID of the AWS Secrets Manager secret.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// Consumes the builder and constructs a [`SecretsManager`](crate::types::SecretsManager).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::SecretsManagerBuilder::arn)
    /// - [`version_id`](crate::types::builders::SecretsManagerBuilder::version_id)
    pub fn build(self) -> ::std::result::Result<crate::types::SecretsManager, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SecretsManager {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building SecretsManager",
                )
            })?,
            version_id: self.version_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "version_id",
                    "version_id was not specified but it is required when building SecretsManager",
                )
            })?,
        })
    }
}
