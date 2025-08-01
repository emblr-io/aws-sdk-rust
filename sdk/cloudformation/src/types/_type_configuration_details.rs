// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Detailed information concerning the specification of a CloudFormation extension in a given account and Region.</p>
/// <p>For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-set-configuration.html">Edit configuration data for extensions in your account</a> in the <i>CloudFormation User Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TypeConfigurationDetails {
    /// <p>The Amazon Resource Name (ARN) for the configuration data, in this account and Region.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The alias specified for this configuration, if one was specified when the configuration was set.</p>
    pub alias: ::std::option::Option<::std::string::String>,
    /// <p>A JSON string specifying the configuration data for the extension, in this account and Region.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>{}</code>.</p>
    pub configuration: ::std::option::Option<::std::string::String>,
    /// <p>When the configuration data was last updated for this extension.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>null</code>.</p>
    pub last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) for the extension, in this account and Region.</p>
    /// <p>For public extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in this account and Region. For private extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a> API operation in this account and Region.</p>
    pub type_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the extension.</p>
    pub type_name: ::std::option::Option<::std::string::String>,
    /// <p>Whether this configuration data is the default configuration for the extension.</p>
    pub is_default_configuration: ::std::option::Option<bool>,
}
impl TypeConfigurationDetails {
    /// <p>The Amazon Resource Name (ARN) for the configuration data, in this account and Region.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The alias specified for this configuration, if one was specified when the configuration was set.</p>
    pub fn alias(&self) -> ::std::option::Option<&str> {
        self.alias.as_deref()
    }
    /// <p>A JSON string specifying the configuration data for the extension, in this account and Region.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>{}</code>.</p>
    pub fn configuration(&self) -> ::std::option::Option<&str> {
        self.configuration.as_deref()
    }
    /// <p>When the configuration data was last updated for this extension.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>null</code>.</p>
    pub fn last_updated(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) for the extension, in this account and Region.</p>
    /// <p>For public extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in this account and Region. For private extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a> API operation in this account and Region.</p>
    pub fn type_arn(&self) -> ::std::option::Option<&str> {
        self.type_arn.as_deref()
    }
    /// <p>The name of the extension.</p>
    pub fn type_name(&self) -> ::std::option::Option<&str> {
        self.type_name.as_deref()
    }
    /// <p>Whether this configuration data is the default configuration for the extension.</p>
    pub fn is_default_configuration(&self) -> ::std::option::Option<bool> {
        self.is_default_configuration
    }
}
impl TypeConfigurationDetails {
    /// Creates a new builder-style object to manufacture [`TypeConfigurationDetails`](crate::types::TypeConfigurationDetails).
    pub fn builder() -> crate::types::builders::TypeConfigurationDetailsBuilder {
        crate::types::builders::TypeConfigurationDetailsBuilder::default()
    }
}

/// A builder for [`TypeConfigurationDetails`](crate::types::TypeConfigurationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TypeConfigurationDetailsBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) alias: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) type_arn: ::std::option::Option<::std::string::String>,
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
    pub(crate) is_default_configuration: ::std::option::Option<bool>,
}
impl TypeConfigurationDetailsBuilder {
    /// <p>The Amazon Resource Name (ARN) for the configuration data, in this account and Region.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the configuration data, in this account and Region.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the configuration data, in this account and Region.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The alias specified for this configuration, if one was specified when the configuration was set.</p>
    pub fn alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The alias specified for this configuration, if one was specified when the configuration was set.</p>
    pub fn set_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias = input;
        self
    }
    /// <p>The alias specified for this configuration, if one was specified when the configuration was set.</p>
    pub fn get_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias
    }
    /// <p>A JSON string specifying the configuration data for the extension, in this account and Region.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>{}</code>.</p>
    pub fn configuration(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A JSON string specifying the configuration data for the extension, in this account and Region.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>{}</code>.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>A JSON string specifying the configuration data for the extension, in this account and Region.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>{}</code>.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration
    }
    /// <p>When the configuration data was last updated for this extension.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>null</code>.</p>
    pub fn last_updated(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the configuration data was last updated for this extension.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>null</code>.</p>
    pub fn set_last_updated(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated = input;
        self
    }
    /// <p>When the configuration data was last updated for this extension.</p>
    /// <p>If a configuration hasn't been set for a specified extension, CloudFormation returns <code>null</code>.</p>
    pub fn get_last_updated(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated
    }
    /// <p>The Amazon Resource Name (ARN) for the extension, in this account and Region.</p>
    /// <p>For public extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in this account and Region. For private extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a> API operation in this account and Region.</p>
    pub fn type_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the extension, in this account and Region.</p>
    /// <p>For public extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in this account and Region. For private extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a> API operation in this account and Region.</p>
    pub fn set_type_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the extension, in this account and Region.</p>
    /// <p>For public extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in this account and Region. For private extensions, this will be the ARN assigned when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a> API operation in this account and Region.</p>
    pub fn get_type_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_arn
    }
    /// <p>The name of the extension.</p>
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the extension.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>The name of the extension.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    /// <p>Whether this configuration data is the default configuration for the extension.</p>
    pub fn is_default_configuration(mut self, input: bool) -> Self {
        self.is_default_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether this configuration data is the default configuration for the extension.</p>
    pub fn set_is_default_configuration(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_default_configuration = input;
        self
    }
    /// <p>Whether this configuration data is the default configuration for the extension.</p>
    pub fn get_is_default_configuration(&self) -> &::std::option::Option<bool> {
        &self.is_default_configuration
    }
    /// Consumes the builder and constructs a [`TypeConfigurationDetails`](crate::types::TypeConfigurationDetails).
    pub fn build(self) -> crate::types::TypeConfigurationDetails {
        crate::types::TypeConfigurationDetails {
            arn: self.arn,
            alias: self.alias,
            configuration: self.configuration,
            last_updated: self.last_updated,
            type_arn: self.type_arn,
            type_name: self.type_name,
            is_default_configuration: self.is_default_configuration,
        }
    }
}
