// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActivateTypeInput {
    /// <p>The extension type.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub r#type: ::std::option::Option<crate::types::ThirdPartyType>,
    /// <p>The Amazon Resource Name (ARN) of the public extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub public_type_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the extension publisher.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub publisher_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub type_name: ::std::option::Option<::std::string::String>,
    /// <p>An alias to assign to the public extension, in this account and Region. If you specify an alias for the extension, CloudFormation treats the alias as the extension type name within this account and Region. You must use the alias to refer to the extension in your templates, API calls, and CloudFormation console.</p>
    /// <p>An extension alias must be unique within a given account and Region. You can activate the same public resource multiple times in the same account and Region, using different type name aliases.</p>
    pub type_name_alias: ::std::option::Option<::std::string::String>,
    /// <p>Whether to automatically update the extension in this account and Region when a new <i>minor</i> version is published by the extension publisher. Major versions released by the publisher must be manually updated.</p>
    /// <p>The default is <code>true</code>.</p>
    pub auto_update: ::std::option::Option<bool>,
    /// <p>Contains logging configuration information for an extension.</p>
    pub logging_config: ::std::option::Option<crate::types::LoggingConfig>,
    /// <p>The name of the IAM execution role to use to activate the extension.</p>
    pub execution_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Manually updates a previously-activated type to a new major or minor version, if available. You can also use this parameter to update the value of <code>AutoUpdate</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>MAJOR</code>: CloudFormation updates the extension to the newest major version, if one is available.</p></li>
    /// <li>
    /// <p><code>MINOR</code>: CloudFormation updates the extension to the newest minor version, if one is available.</p></li>
    /// </ul>
    pub version_bump: ::std::option::Option<crate::types::VersionBump>,
    /// <p>The major version of this extension you want to activate, if multiple major versions are available. The default is the latest major version. CloudFormation uses the latest available <i>minor</i> version of the major version selected.</p>
    /// <p>You can specify <code>MajorVersion</code> or <code>VersionBump</code>, but not both.</p>
    pub major_version: ::std::option::Option<i64>,
}
impl ActivateTypeInput {
    /// <p>The extension type.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::ThirdPartyType> {
        self.r#type.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the public extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn public_type_arn(&self) -> ::std::option::Option<&str> {
        self.public_type_arn.as_deref()
    }
    /// <p>The ID of the extension publisher.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn publisher_id(&self) -> ::std::option::Option<&str> {
        self.publisher_id.as_deref()
    }
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn type_name(&self) -> ::std::option::Option<&str> {
        self.type_name.as_deref()
    }
    /// <p>An alias to assign to the public extension, in this account and Region. If you specify an alias for the extension, CloudFormation treats the alias as the extension type name within this account and Region. You must use the alias to refer to the extension in your templates, API calls, and CloudFormation console.</p>
    /// <p>An extension alias must be unique within a given account and Region. You can activate the same public resource multiple times in the same account and Region, using different type name aliases.</p>
    pub fn type_name_alias(&self) -> ::std::option::Option<&str> {
        self.type_name_alias.as_deref()
    }
    /// <p>Whether to automatically update the extension in this account and Region when a new <i>minor</i> version is published by the extension publisher. Major versions released by the publisher must be manually updated.</p>
    /// <p>The default is <code>true</code>.</p>
    pub fn auto_update(&self) -> ::std::option::Option<bool> {
        self.auto_update
    }
    /// <p>Contains logging configuration information for an extension.</p>
    pub fn logging_config(&self) -> ::std::option::Option<&crate::types::LoggingConfig> {
        self.logging_config.as_ref()
    }
    /// <p>The name of the IAM execution role to use to activate the extension.</p>
    pub fn execution_role_arn(&self) -> ::std::option::Option<&str> {
        self.execution_role_arn.as_deref()
    }
    /// <p>Manually updates a previously-activated type to a new major or minor version, if available. You can also use this parameter to update the value of <code>AutoUpdate</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>MAJOR</code>: CloudFormation updates the extension to the newest major version, if one is available.</p></li>
    /// <li>
    /// <p><code>MINOR</code>: CloudFormation updates the extension to the newest minor version, if one is available.</p></li>
    /// </ul>
    pub fn version_bump(&self) -> ::std::option::Option<&crate::types::VersionBump> {
        self.version_bump.as_ref()
    }
    /// <p>The major version of this extension you want to activate, if multiple major versions are available. The default is the latest major version. CloudFormation uses the latest available <i>minor</i> version of the major version selected.</p>
    /// <p>You can specify <code>MajorVersion</code> or <code>VersionBump</code>, but not both.</p>
    pub fn major_version(&self) -> ::std::option::Option<i64> {
        self.major_version
    }
}
impl ActivateTypeInput {
    /// Creates a new builder-style object to manufacture [`ActivateTypeInput`](crate::operation::activate_type::ActivateTypeInput).
    pub fn builder() -> crate::operation::activate_type::builders::ActivateTypeInputBuilder {
        crate::operation::activate_type::builders::ActivateTypeInputBuilder::default()
    }
}

/// A builder for [`ActivateTypeInput`](crate::operation::activate_type::ActivateTypeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActivateTypeInputBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::ThirdPartyType>,
    pub(crate) public_type_arn: ::std::option::Option<::std::string::String>,
    pub(crate) publisher_id: ::std::option::Option<::std::string::String>,
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
    pub(crate) type_name_alias: ::std::option::Option<::std::string::String>,
    pub(crate) auto_update: ::std::option::Option<bool>,
    pub(crate) logging_config: ::std::option::Option<crate::types::LoggingConfig>,
    pub(crate) execution_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) version_bump: ::std::option::Option<crate::types::VersionBump>,
    pub(crate) major_version: ::std::option::Option<i64>,
}
impl ActivateTypeInputBuilder {
    /// <p>The extension type.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn r#type(mut self, input: crate::types::ThirdPartyType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The extension type.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ThirdPartyType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The extension type.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ThirdPartyType> {
        &self.r#type
    }
    /// <p>The Amazon Resource Name (ARN) of the public extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn public_type_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_type_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the public extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn set_public_type_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_type_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the public extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn get_public_type_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_type_arn
    }
    /// <p>The ID of the extension publisher.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn publisher_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.publisher_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the extension publisher.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn set_publisher_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.publisher_id = input;
        self
    }
    /// <p>The ID of the extension publisher.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn get_publisher_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.publisher_id
    }
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>The name of the extension.</p>
    /// <p>Conditional: You must specify <code>PublicTypeArn</code>, or <code>TypeName</code>, <code>Type</code>, and <code>PublisherId</code>.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    /// <p>An alias to assign to the public extension, in this account and Region. If you specify an alias for the extension, CloudFormation treats the alias as the extension type name within this account and Region. You must use the alias to refer to the extension in your templates, API calls, and CloudFormation console.</p>
    /// <p>An extension alias must be unique within a given account and Region. You can activate the same public resource multiple times in the same account and Region, using different type name aliases.</p>
    pub fn type_name_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An alias to assign to the public extension, in this account and Region. If you specify an alias for the extension, CloudFormation treats the alias as the extension type name within this account and Region. You must use the alias to refer to the extension in your templates, API calls, and CloudFormation console.</p>
    /// <p>An extension alias must be unique within a given account and Region. You can activate the same public resource multiple times in the same account and Region, using different type name aliases.</p>
    pub fn set_type_name_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name_alias = input;
        self
    }
    /// <p>An alias to assign to the public extension, in this account and Region. If you specify an alias for the extension, CloudFormation treats the alias as the extension type name within this account and Region. You must use the alias to refer to the extension in your templates, API calls, and CloudFormation console.</p>
    /// <p>An extension alias must be unique within a given account and Region. You can activate the same public resource multiple times in the same account and Region, using different type name aliases.</p>
    pub fn get_type_name_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name_alias
    }
    /// <p>Whether to automatically update the extension in this account and Region when a new <i>minor</i> version is published by the extension publisher. Major versions released by the publisher must be manually updated.</p>
    /// <p>The default is <code>true</code>.</p>
    pub fn auto_update(mut self, input: bool) -> Self {
        self.auto_update = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether to automatically update the extension in this account and Region when a new <i>minor</i> version is published by the extension publisher. Major versions released by the publisher must be manually updated.</p>
    /// <p>The default is <code>true</code>.</p>
    pub fn set_auto_update(mut self, input: ::std::option::Option<bool>) -> Self {
        self.auto_update = input;
        self
    }
    /// <p>Whether to automatically update the extension in this account and Region when a new <i>minor</i> version is published by the extension publisher. Major versions released by the publisher must be manually updated.</p>
    /// <p>The default is <code>true</code>.</p>
    pub fn get_auto_update(&self) -> &::std::option::Option<bool> {
        &self.auto_update
    }
    /// <p>Contains logging configuration information for an extension.</p>
    pub fn logging_config(mut self, input: crate::types::LoggingConfig) -> Self {
        self.logging_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains logging configuration information for an extension.</p>
    pub fn set_logging_config(mut self, input: ::std::option::Option<crate::types::LoggingConfig>) -> Self {
        self.logging_config = input;
        self
    }
    /// <p>Contains logging configuration information for an extension.</p>
    pub fn get_logging_config(&self) -> &::std::option::Option<crate::types::LoggingConfig> {
        &self.logging_config
    }
    /// <p>The name of the IAM execution role to use to activate the extension.</p>
    pub fn execution_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IAM execution role to use to activate the extension.</p>
    pub fn set_execution_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role_arn = input;
        self
    }
    /// <p>The name of the IAM execution role to use to activate the extension.</p>
    pub fn get_execution_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role_arn
    }
    /// <p>Manually updates a previously-activated type to a new major or minor version, if available. You can also use this parameter to update the value of <code>AutoUpdate</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>MAJOR</code>: CloudFormation updates the extension to the newest major version, if one is available.</p></li>
    /// <li>
    /// <p><code>MINOR</code>: CloudFormation updates the extension to the newest minor version, if one is available.</p></li>
    /// </ul>
    pub fn version_bump(mut self, input: crate::types::VersionBump) -> Self {
        self.version_bump = ::std::option::Option::Some(input);
        self
    }
    /// <p>Manually updates a previously-activated type to a new major or minor version, if available. You can also use this parameter to update the value of <code>AutoUpdate</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>MAJOR</code>: CloudFormation updates the extension to the newest major version, if one is available.</p></li>
    /// <li>
    /// <p><code>MINOR</code>: CloudFormation updates the extension to the newest minor version, if one is available.</p></li>
    /// </ul>
    pub fn set_version_bump(mut self, input: ::std::option::Option<crate::types::VersionBump>) -> Self {
        self.version_bump = input;
        self
    }
    /// <p>Manually updates a previously-activated type to a new major or minor version, if available. You can also use this parameter to update the value of <code>AutoUpdate</code>.</p>
    /// <ul>
    /// <li>
    /// <p><code>MAJOR</code>: CloudFormation updates the extension to the newest major version, if one is available.</p></li>
    /// <li>
    /// <p><code>MINOR</code>: CloudFormation updates the extension to the newest minor version, if one is available.</p></li>
    /// </ul>
    pub fn get_version_bump(&self) -> &::std::option::Option<crate::types::VersionBump> {
        &self.version_bump
    }
    /// <p>The major version of this extension you want to activate, if multiple major versions are available. The default is the latest major version. CloudFormation uses the latest available <i>minor</i> version of the major version selected.</p>
    /// <p>You can specify <code>MajorVersion</code> or <code>VersionBump</code>, but not both.</p>
    pub fn major_version(mut self, input: i64) -> Self {
        self.major_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The major version of this extension you want to activate, if multiple major versions are available. The default is the latest major version. CloudFormation uses the latest available <i>minor</i> version of the major version selected.</p>
    /// <p>You can specify <code>MajorVersion</code> or <code>VersionBump</code>, but not both.</p>
    pub fn set_major_version(mut self, input: ::std::option::Option<i64>) -> Self {
        self.major_version = input;
        self
    }
    /// <p>The major version of this extension you want to activate, if multiple major versions are available. The default is the latest major version. CloudFormation uses the latest available <i>minor</i> version of the major version selected.</p>
    /// <p>You can specify <code>MajorVersion</code> or <code>VersionBump</code>, but not both.</p>
    pub fn get_major_version(&self) -> &::std::option::Option<i64> {
        &self.major_version
    }
    /// Consumes the builder and constructs a [`ActivateTypeInput`](crate::operation::activate_type::ActivateTypeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::activate_type::ActivateTypeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::activate_type::ActivateTypeInput {
            r#type: self.r#type,
            public_type_arn: self.public_type_arn,
            publisher_id: self.publisher_id,
            type_name: self.type_name,
            type_name_alias: self.type_name_alias,
            auto_update: self.auto_update,
            logging_config: self.logging_config,
            execution_role_arn: self.execution_role_arn,
            version_bump: self.version_bump,
            major_version: self.major_version,
        })
    }
}
