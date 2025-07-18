// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutDefaultEncryptionConfigurationOutput {
    /// <p>Provides the status of the default encryption configuration for an Amazon Web Services account.</p>
    pub configuration_status: ::std::option::Option<crate::types::ConfigurationStatus>,
    /// <p>The type of encryption used for the encryption configuration.</p>
    pub encryption_type: crate::types::EncryptionType,
    /// <p>The Key Amazon Resource Name (ARN) of the AWS KMS key used for KMS encryption if you use <code>KMS_BASED_ENCRYPTION</code>.</p>
    pub kms_key_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutDefaultEncryptionConfigurationOutput {
    /// <p>Provides the status of the default encryption configuration for an Amazon Web Services account.</p>
    pub fn configuration_status(&self) -> ::std::option::Option<&crate::types::ConfigurationStatus> {
        self.configuration_status.as_ref()
    }
    /// <p>The type of encryption used for the encryption configuration.</p>
    pub fn encryption_type(&self) -> &crate::types::EncryptionType {
        &self.encryption_type
    }
    /// <p>The Key Amazon Resource Name (ARN) of the AWS KMS key used for KMS encryption if you use <code>KMS_BASED_ENCRYPTION</code>.</p>
    pub fn kms_key_arn(&self) -> ::std::option::Option<&str> {
        self.kms_key_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for PutDefaultEncryptionConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutDefaultEncryptionConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`PutDefaultEncryptionConfigurationOutput`](crate::operation::put_default_encryption_configuration::PutDefaultEncryptionConfigurationOutput).
    pub fn builder() -> crate::operation::put_default_encryption_configuration::builders::PutDefaultEncryptionConfigurationOutputBuilder {
        crate::operation::put_default_encryption_configuration::builders::PutDefaultEncryptionConfigurationOutputBuilder::default()
    }
}

/// A builder for [`PutDefaultEncryptionConfigurationOutput`](crate::operation::put_default_encryption_configuration::PutDefaultEncryptionConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutDefaultEncryptionConfigurationOutputBuilder {
    pub(crate) configuration_status: ::std::option::Option<crate::types::ConfigurationStatus>,
    pub(crate) encryption_type: ::std::option::Option<crate::types::EncryptionType>,
    pub(crate) kms_key_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutDefaultEncryptionConfigurationOutputBuilder {
    /// <p>Provides the status of the default encryption configuration for an Amazon Web Services account.</p>
    /// This field is required.
    pub fn configuration_status(mut self, input: crate::types::ConfigurationStatus) -> Self {
        self.configuration_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides the status of the default encryption configuration for an Amazon Web Services account.</p>
    pub fn set_configuration_status(mut self, input: ::std::option::Option<crate::types::ConfigurationStatus>) -> Self {
        self.configuration_status = input;
        self
    }
    /// <p>Provides the status of the default encryption configuration for an Amazon Web Services account.</p>
    pub fn get_configuration_status(&self) -> &::std::option::Option<crate::types::ConfigurationStatus> {
        &self.configuration_status
    }
    /// <p>The type of encryption used for the encryption configuration.</p>
    /// This field is required.
    pub fn encryption_type(mut self, input: crate::types::EncryptionType) -> Self {
        self.encryption_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of encryption used for the encryption configuration.</p>
    pub fn set_encryption_type(mut self, input: ::std::option::Option<crate::types::EncryptionType>) -> Self {
        self.encryption_type = input;
        self
    }
    /// <p>The type of encryption used for the encryption configuration.</p>
    pub fn get_encryption_type(&self) -> &::std::option::Option<crate::types::EncryptionType> {
        &self.encryption_type
    }
    /// <p>The Key Amazon Resource Name (ARN) of the AWS KMS key used for KMS encryption if you use <code>KMS_BASED_ENCRYPTION</code>.</p>
    pub fn kms_key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Key Amazon Resource Name (ARN) of the AWS KMS key used for KMS encryption if you use <code>KMS_BASED_ENCRYPTION</code>.</p>
    pub fn set_kms_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_arn = input;
        self
    }
    /// <p>The Key Amazon Resource Name (ARN) of the AWS KMS key used for KMS encryption if you use <code>KMS_BASED_ENCRYPTION</code>.</p>
    pub fn get_kms_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutDefaultEncryptionConfigurationOutput`](crate::operation::put_default_encryption_configuration::PutDefaultEncryptionConfigurationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`encryption_type`](crate::operation::put_default_encryption_configuration::builders::PutDefaultEncryptionConfigurationOutputBuilder::encryption_type)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_default_encryption_configuration::PutDefaultEncryptionConfigurationOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_default_encryption_configuration::PutDefaultEncryptionConfigurationOutput {
                configuration_status: self.configuration_status,
                encryption_type: self.encryption_type.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "encryption_type",
                        "encryption_type was not specified but it is required when building PutDefaultEncryptionConfigurationOutput",
                    )
                })?,
                kms_key_arn: self.kms_key_arn,
                _request_id: self._request_id,
            },
        )
    }
}
