// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains configuration about the session with the knowledge base.</p>
/// <p>This data type is used in the following API operations:</p>
/// <ul>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_RetrieveAndGenerate.html#API_agent-runtime_RetrieveAndGenerate_RequestSyntax">RetrieveAndGenerate request</a> – in the <code>sessionConfiguration</code> field</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RetrieveAndGenerateSessionConfiguration {
    /// <p>The ARN of the KMS key encrypting the session.</p>
    pub kms_key_arn: ::std::string::String,
}
impl RetrieveAndGenerateSessionConfiguration {
    /// <p>The ARN of the KMS key encrypting the session.</p>
    pub fn kms_key_arn(&self) -> &str {
        use std::ops::Deref;
        self.kms_key_arn.deref()
    }
}
impl RetrieveAndGenerateSessionConfiguration {
    /// Creates a new builder-style object to manufacture [`RetrieveAndGenerateSessionConfiguration`](crate::types::RetrieveAndGenerateSessionConfiguration).
    pub fn builder() -> crate::types::builders::RetrieveAndGenerateSessionConfigurationBuilder {
        crate::types::builders::RetrieveAndGenerateSessionConfigurationBuilder::default()
    }
}

/// A builder for [`RetrieveAndGenerateSessionConfiguration`](crate::types::RetrieveAndGenerateSessionConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RetrieveAndGenerateSessionConfigurationBuilder {
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
}
impl RetrieveAndGenerateSessionConfigurationBuilder {
    /// <p>The ARN of the KMS key encrypting the session.</p>
    /// This field is required.
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the KMS key encrypting the session.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The ARN of the KMS key encrypting the session.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    /// Consumes the builder and constructs a [`RetrieveAndGenerateSessionConfiguration`](crate::types::RetrieveAndGenerateSessionConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`kms_key_arn`](crate::types::builders::RetrieveAndGenerateSessionConfigurationBuilder::kms_key_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::RetrieveAndGenerateSessionConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RetrieveAndGenerateSessionConfiguration {
            kms_key_arn: self.kms_key_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "kms_key_arn",
                    "kms_key_arn was not specified but it is required when building RetrieveAndGenerateSessionConfiguration",
                )
            })?,
        })
    }
}
