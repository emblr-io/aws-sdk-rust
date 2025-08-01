// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the Amazon S3 location of the training data you want to use to create a new custom language model, and permissions to access this location.</p>
/// <p>When using <code>InputDataConfig</code>, you must include these sub-parameters: <code>S3Uri</code> and <code>DataAccessRoleArn</code>. You can optionally include <code>TuningDataS3Uri</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InputDataConfig {
    /// <p>The Amazon S3 location (URI) of the text files you want to use to train your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-training-data/</code></p>
    pub s3_uri: ::std::string::String,
    /// <p>The Amazon S3 location (URI) of the text files you want to use to tune your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-tuning-data/</code></p>
    pub tuning_data_s3_uri: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of an IAM role that has permissions to access the Amazon S3 bucket that contains your input files. If the role that you specify doesn’t have the appropriate permissions to access the specified Amazon S3 location, your request fails.</p>
    /// <p>IAM role ARNs have the format <code>arn:partition:iam::account:role/role-name-with-path</code>. For example: <code>arn:aws:iam::111122223333:role/Admin</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns">IAM ARNs</a>.</p>
    pub data_access_role_arn: ::std::string::String,
}
impl InputDataConfig {
    /// <p>The Amazon S3 location (URI) of the text files you want to use to train your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-training-data/</code></p>
    pub fn s3_uri(&self) -> &str {
        use std::ops::Deref;
        self.s3_uri.deref()
    }
    /// <p>The Amazon S3 location (URI) of the text files you want to use to tune your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-tuning-data/</code></p>
    pub fn tuning_data_s3_uri(&self) -> ::std::option::Option<&str> {
        self.tuning_data_s3_uri.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that has permissions to access the Amazon S3 bucket that contains your input files. If the role that you specify doesn’t have the appropriate permissions to access the specified Amazon S3 location, your request fails.</p>
    /// <p>IAM role ARNs have the format <code>arn:partition:iam::account:role/role-name-with-path</code>. For example: <code>arn:aws:iam::111122223333:role/Admin</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns">IAM ARNs</a>.</p>
    pub fn data_access_role_arn(&self) -> &str {
        use std::ops::Deref;
        self.data_access_role_arn.deref()
    }
}
impl InputDataConfig {
    /// Creates a new builder-style object to manufacture [`InputDataConfig`](crate::types::InputDataConfig).
    pub fn builder() -> crate::types::builders::InputDataConfigBuilder {
        crate::types::builders::InputDataConfigBuilder::default()
    }
}

/// A builder for [`InputDataConfig`](crate::types::InputDataConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InputDataConfigBuilder {
    pub(crate) s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) tuning_data_s3_uri: ::std::option::Option<::std::string::String>,
    pub(crate) data_access_role_arn: ::std::option::Option<::std::string::String>,
}
impl InputDataConfigBuilder {
    /// <p>The Amazon S3 location (URI) of the text files you want to use to train your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-training-data/</code></p>
    /// This field is required.
    pub fn s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 location (URI) of the text files you want to use to train your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-training-data/</code></p>
    pub fn set_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.s3_uri = input;
        self
    }
    /// <p>The Amazon S3 location (URI) of the text files you want to use to train your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-training-data/</code></p>
    pub fn get_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.s3_uri
    }
    /// <p>The Amazon S3 location (URI) of the text files you want to use to tune your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-tuning-data/</code></p>
    pub fn tuning_data_s3_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tuning_data_s3_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 location (URI) of the text files you want to use to tune your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-tuning-data/</code></p>
    pub fn set_tuning_data_s3_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tuning_data_s3_uri = input;
        self
    }
    /// <p>The Amazon S3 location (URI) of the text files you want to use to tune your custom language model.</p>
    /// <p>Here's an example URI path: <code>s3://DOC-EXAMPLE-BUCKET/my-model-tuning-data/</code></p>
    pub fn get_tuning_data_s3_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.tuning_data_s3_uri
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that has permissions to access the Amazon S3 bucket that contains your input files. If the role that you specify doesn’t have the appropriate permissions to access the specified Amazon S3 location, your request fails.</p>
    /// <p>IAM role ARNs have the format <code>arn:partition:iam::account:role/role-name-with-path</code>. For example: <code>arn:aws:iam::111122223333:role/Admin</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns">IAM ARNs</a>.</p>
    /// This field is required.
    pub fn data_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that has permissions to access the Amazon S3 bucket that contains your input files. If the role that you specify doesn’t have the appropriate permissions to access the specified Amazon S3 location, your request fails.</p>
    /// <p>IAM role ARNs have the format <code>arn:partition:iam::account:role/role-name-with-path</code>. For example: <code>arn:aws:iam::111122223333:role/Admin</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns">IAM ARNs</a>.</p>
    pub fn set_data_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_access_role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of an IAM role that has permissions to access the Amazon S3 bucket that contains your input files. If the role that you specify doesn’t have the appropriate permissions to access the specified Amazon S3 location, your request fails.</p>
    /// <p>IAM role ARNs have the format <code>arn:partition:iam::account:role/role-name-with-path</code>. For example: <code>arn:aws:iam::111122223333:role/Admin</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html#identifiers-arns">IAM ARNs</a>.</p>
    pub fn get_data_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_access_role_arn
    }
    /// Consumes the builder and constructs a [`InputDataConfig`](crate::types::InputDataConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`s3_uri`](crate::types::builders::InputDataConfigBuilder::s3_uri)
    /// - [`data_access_role_arn`](crate::types::builders::InputDataConfigBuilder::data_access_role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::InputDataConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::InputDataConfig {
            s3_uri: self.s3_uri.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "s3_uri",
                    "s3_uri was not specified but it is required when building InputDataConfig",
                )
            })?,
            tuning_data_s3_uri: self.tuning_data_s3_uri,
            data_access_role_arn: self.data_access_role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_access_role_arn",
                    "data_access_role_arn was not specified but it is required when building InputDataConfig",
                )
            })?,
        })
    }
}
