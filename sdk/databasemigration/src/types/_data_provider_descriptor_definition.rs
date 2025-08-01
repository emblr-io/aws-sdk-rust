// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a data provider.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataProviderDescriptorDefinition {
    /// <p>The name or Amazon Resource Name (ARN) of the data provider.</p>
    pub data_provider_identifier: ::std::string::String,
    /// <p>The identifier of the Amazon Web Services Secrets Manager Secret used to store access credentials for the data provider.</p>
    pub secrets_manager_secret_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the role used to access Amazon Web Services Secrets Manager.</p>
    pub secrets_manager_access_role_arn: ::std::option::Option<::std::string::String>,
}
impl DataProviderDescriptorDefinition {
    /// <p>The name or Amazon Resource Name (ARN) of the data provider.</p>
    pub fn data_provider_identifier(&self) -> &str {
        use std::ops::Deref;
        self.data_provider_identifier.deref()
    }
    /// <p>The identifier of the Amazon Web Services Secrets Manager Secret used to store access credentials for the data provider.</p>
    pub fn secrets_manager_secret_id(&self) -> ::std::option::Option<&str> {
        self.secrets_manager_secret_id.as_deref()
    }
    /// <p>The ARN of the role used to access Amazon Web Services Secrets Manager.</p>
    pub fn secrets_manager_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.secrets_manager_access_role_arn.as_deref()
    }
}
impl DataProviderDescriptorDefinition {
    /// Creates a new builder-style object to manufacture [`DataProviderDescriptorDefinition`](crate::types::DataProviderDescriptorDefinition).
    pub fn builder() -> crate::types::builders::DataProviderDescriptorDefinitionBuilder {
        crate::types::builders::DataProviderDescriptorDefinitionBuilder::default()
    }
}

/// A builder for [`DataProviderDescriptorDefinition`](crate::types::DataProviderDescriptorDefinition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataProviderDescriptorDefinitionBuilder {
    pub(crate) data_provider_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) secrets_manager_secret_id: ::std::option::Option<::std::string::String>,
    pub(crate) secrets_manager_access_role_arn: ::std::option::Option<::std::string::String>,
}
impl DataProviderDescriptorDefinitionBuilder {
    /// <p>The name or Amazon Resource Name (ARN) of the data provider.</p>
    /// This field is required.
    pub fn data_provider_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_provider_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the data provider.</p>
    pub fn set_data_provider_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_provider_identifier = input;
        self
    }
    /// <p>The name or Amazon Resource Name (ARN) of the data provider.</p>
    pub fn get_data_provider_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_provider_identifier
    }
    /// <p>The identifier of the Amazon Web Services Secrets Manager Secret used to store access credentials for the data provider.</p>
    pub fn secrets_manager_secret_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secrets_manager_secret_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Web Services Secrets Manager Secret used to store access credentials for the data provider.</p>
    pub fn set_secrets_manager_secret_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secrets_manager_secret_id = input;
        self
    }
    /// <p>The identifier of the Amazon Web Services Secrets Manager Secret used to store access credentials for the data provider.</p>
    pub fn get_secrets_manager_secret_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.secrets_manager_secret_id
    }
    /// <p>The ARN of the role used to access Amazon Web Services Secrets Manager.</p>
    pub fn secrets_manager_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secrets_manager_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the role used to access Amazon Web Services Secrets Manager.</p>
    pub fn set_secrets_manager_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secrets_manager_access_role_arn = input;
        self
    }
    /// <p>The ARN of the role used to access Amazon Web Services Secrets Manager.</p>
    pub fn get_secrets_manager_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.secrets_manager_access_role_arn
    }
    /// Consumes the builder and constructs a [`DataProviderDescriptorDefinition`](crate::types::DataProviderDescriptorDefinition).
    /// This method will fail if any of the following fields are not set:
    /// - [`data_provider_identifier`](crate::types::builders::DataProviderDescriptorDefinitionBuilder::data_provider_identifier)
    pub fn build(self) -> ::std::result::Result<crate::types::DataProviderDescriptorDefinition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataProviderDescriptorDefinition {
            data_provider_identifier: self.data_provider_identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "data_provider_identifier",
                    "data_provider_identifier was not specified but it is required when building DataProviderDescriptorDefinition",
                )
            })?,
            secrets_manager_secret_id: self.secrets_manager_secret_id,
            secrets_manager_access_role_arn: self.secrets_manager_access_role_arn,
        })
    }
}
