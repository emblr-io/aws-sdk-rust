// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSecurityConfigurationInput {
    /// <p>The name for the new security configuration.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The encryption configuration for the new security configuration.</p>
    pub encryption_configuration: ::std::option::Option<crate::types::EncryptionConfiguration>,
}
impl CreateSecurityConfigurationInput {
    /// <p>The name for the new security configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The encryption configuration for the new security configuration.</p>
    pub fn encryption_configuration(&self) -> ::std::option::Option<&crate::types::EncryptionConfiguration> {
        self.encryption_configuration.as_ref()
    }
}
impl CreateSecurityConfigurationInput {
    /// Creates a new builder-style object to manufacture [`CreateSecurityConfigurationInput`](crate::operation::create_security_configuration::CreateSecurityConfigurationInput).
    pub fn builder() -> crate::operation::create_security_configuration::builders::CreateSecurityConfigurationInputBuilder {
        crate::operation::create_security_configuration::builders::CreateSecurityConfigurationInputBuilder::default()
    }
}

/// A builder for [`CreateSecurityConfigurationInput`](crate::operation::create_security_configuration::CreateSecurityConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSecurityConfigurationInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_configuration: ::std::option::Option<crate::types::EncryptionConfiguration>,
}
impl CreateSecurityConfigurationInputBuilder {
    /// <p>The name for the new security configuration.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the new security configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name for the new security configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The encryption configuration for the new security configuration.</p>
    /// This field is required.
    pub fn encryption_configuration(mut self, input: crate::types::EncryptionConfiguration) -> Self {
        self.encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption configuration for the new security configuration.</p>
    pub fn set_encryption_configuration(mut self, input: ::std::option::Option<crate::types::EncryptionConfiguration>) -> Self {
        self.encryption_configuration = input;
        self
    }
    /// <p>The encryption configuration for the new security configuration.</p>
    pub fn get_encryption_configuration(&self) -> &::std::option::Option<crate::types::EncryptionConfiguration> {
        &self.encryption_configuration
    }
    /// Consumes the builder and constructs a [`CreateSecurityConfigurationInput`](crate::operation::create_security_configuration::CreateSecurityConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_security_configuration::CreateSecurityConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_security_configuration::CreateSecurityConfigurationInput {
            name: self.name,
            encryption_configuration: self.encryption_configuration,
        })
    }
}
