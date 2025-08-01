// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains summary information about the specified CloudFormation extension.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TypeSummary {
    /// <p>The kind of extension.</p>
    pub r#type: ::std::option::Option<crate::types::RegistryType>,
    /// <p>The name of the extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in your account and Region, CloudFormation considers that alias as the type name.</p>
    pub type_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the default version of the extension. The default version is used when the extension version isn't specified.</p>
    /// <p>This applies only to private extensions you have registered in your account. For public extensions, both those provided by Amazon and published by third parties, CloudFormation returns <code>null</code>. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p>
    /// <p>To set the default version of an extension, use <code>SetTypeDefaultVersion</code>.</p>
    pub default_version_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub type_arn: ::std::option::Option<::std::string::String>,
    /// <p>When the specified extension version was registered. This applies only to:</p>
    /// <ul>
    /// <li>
    /// <p>Private extensions you have registered in your account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p></li>
    /// <li>
    /// <p>Public extensions you have activated in your account with auto-update specified. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a>.</p></li>
    /// </ul>
    /// <p>For all other extension types, CloudFormation returns <code>null</code>.</p>
    pub last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The description of the extension.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the extension publisher, if the extension is published by a third party. Extensions published by Amazon don't return a publisher ID.</p>
    pub publisher_id: ::std::option::Option<::std::string::String>,
    /// <p>For public extensions that have been activated for this account and Region, the type name of the public extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when enabling the extension in this account and Region, CloudFormation treats that alias as the extension's type name within the account and Region, not the type name of the public extension. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-alias">Use aliases to refer to extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub original_type_name: ::std::option::Option<::std::string::String>,
    /// <p>For public extensions that have been activated for this account and Region, the version of the public extension to be used for CloudFormation operations in this account and Region.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub public_version_number: ::std::option::Option<::std::string::String>,
    /// <p>For public extensions that have been activated for this account and Region, the latest version of the public extension <i>that is available</i>. For any extensions other than activated third-party extensions, CloudFormation returns <code>null</code>.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub latest_public_version: ::std::option::Option<::std::string::String>,
    /// <p>The service used to verify the publisher identity.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/publish-extension.html">Publishing extensions to make them available for public use</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub publisher_identity: ::std::option::Option<crate::types::IdentityProvider>,
    /// <p>The publisher name, as defined in the public profile for that publisher in the service used to verify the publisher identity.</p>
    pub publisher_name: ::std::option::Option<::std::string::String>,
    /// <p>Whether the extension is activated for this account and Region.</p>
    /// <p>This applies only to third-party public extensions. Extensions published by Amazon are activated by default.</p>
    pub is_activated: ::std::option::Option<bool>,
}
impl TypeSummary {
    /// <p>The kind of extension.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::RegistryType> {
        self.r#type.as_ref()
    }
    /// <p>The name of the extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in your account and Region, CloudFormation considers that alias as the type name.</p>
    pub fn type_name(&self) -> ::std::option::Option<&str> {
        self.type_name.as_deref()
    }
    /// <p>The ID of the default version of the extension. The default version is used when the extension version isn't specified.</p>
    /// <p>This applies only to private extensions you have registered in your account. For public extensions, both those provided by Amazon and published by third parties, CloudFormation returns <code>null</code>. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p>
    /// <p>To set the default version of an extension, use <code>SetTypeDefaultVersion</code>.</p>
    pub fn default_version_id(&self) -> ::std::option::Option<&str> {
        self.default_version_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub fn type_arn(&self) -> ::std::option::Option<&str> {
        self.type_arn.as_deref()
    }
    /// <p>When the specified extension version was registered. This applies only to:</p>
    /// <ul>
    /// <li>
    /// <p>Private extensions you have registered in your account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p></li>
    /// <li>
    /// <p>Public extensions you have activated in your account with auto-update specified. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a>.</p></li>
    /// </ul>
    /// <p>For all other extension types, CloudFormation returns <code>null</code>.</p>
    pub fn last_updated(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated.as_ref()
    }
    /// <p>The description of the extension.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The ID of the extension publisher, if the extension is published by a third party. Extensions published by Amazon don't return a publisher ID.</p>
    pub fn publisher_id(&self) -> ::std::option::Option<&str> {
        self.publisher_id.as_deref()
    }
    /// <p>For public extensions that have been activated for this account and Region, the type name of the public extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when enabling the extension in this account and Region, CloudFormation treats that alias as the extension's type name within the account and Region, not the type name of the public extension. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-alias">Use aliases to refer to extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn original_type_name(&self) -> ::std::option::Option<&str> {
        self.original_type_name.as_deref()
    }
    /// <p>For public extensions that have been activated for this account and Region, the version of the public extension to be used for CloudFormation operations in this account and Region.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn public_version_number(&self) -> ::std::option::Option<&str> {
        self.public_version_number.as_deref()
    }
    /// <p>For public extensions that have been activated for this account and Region, the latest version of the public extension <i>that is available</i>. For any extensions other than activated third-party extensions, CloudFormation returns <code>null</code>.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn latest_public_version(&self) -> ::std::option::Option<&str> {
        self.latest_public_version.as_deref()
    }
    /// <p>The service used to verify the publisher identity.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/publish-extension.html">Publishing extensions to make them available for public use</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub fn publisher_identity(&self) -> ::std::option::Option<&crate::types::IdentityProvider> {
        self.publisher_identity.as_ref()
    }
    /// <p>The publisher name, as defined in the public profile for that publisher in the service used to verify the publisher identity.</p>
    pub fn publisher_name(&self) -> ::std::option::Option<&str> {
        self.publisher_name.as_deref()
    }
    /// <p>Whether the extension is activated for this account and Region.</p>
    /// <p>This applies only to third-party public extensions. Extensions published by Amazon are activated by default.</p>
    pub fn is_activated(&self) -> ::std::option::Option<bool> {
        self.is_activated
    }
}
impl TypeSummary {
    /// Creates a new builder-style object to manufacture [`TypeSummary`](crate::types::TypeSummary).
    pub fn builder() -> crate::types::builders::TypeSummaryBuilder {
        crate::types::builders::TypeSummaryBuilder::default()
    }
}

/// A builder for [`TypeSummary`](crate::types::TypeSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TypeSummaryBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::RegistryType>,
    pub(crate) type_name: ::std::option::Option<::std::string::String>,
    pub(crate) default_version_id: ::std::option::Option<::std::string::String>,
    pub(crate) type_arn: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) publisher_id: ::std::option::Option<::std::string::String>,
    pub(crate) original_type_name: ::std::option::Option<::std::string::String>,
    pub(crate) public_version_number: ::std::option::Option<::std::string::String>,
    pub(crate) latest_public_version: ::std::option::Option<::std::string::String>,
    pub(crate) publisher_identity: ::std::option::Option<crate::types::IdentityProvider>,
    pub(crate) publisher_name: ::std::option::Option<::std::string::String>,
    pub(crate) is_activated: ::std::option::Option<bool>,
}
impl TypeSummaryBuilder {
    /// <p>The kind of extension.</p>
    pub fn r#type(mut self, input: crate::types::RegistryType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The kind of extension.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RegistryType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The kind of extension.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RegistryType> {
        &self.r#type
    }
    /// <p>The name of the extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in your account and Region, CloudFormation considers that alias as the type name.</p>
    pub fn type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in your account and Region, CloudFormation considers that alias as the type name.</p>
    pub fn set_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_name = input;
        self
    }
    /// <p>The name of the extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when you call the <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a> API operation in your account and Region, CloudFormation considers that alias as the type name.</p>
    pub fn get_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_name
    }
    /// <p>The ID of the default version of the extension. The default version is used when the extension version isn't specified.</p>
    /// <p>This applies only to private extensions you have registered in your account. For public extensions, both those provided by Amazon and published by third parties, CloudFormation returns <code>null</code>. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p>
    /// <p>To set the default version of an extension, use <code>SetTypeDefaultVersion</code>.</p>
    pub fn default_version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.default_version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the default version of the extension. The default version is used when the extension version isn't specified.</p>
    /// <p>This applies only to private extensions you have registered in your account. For public extensions, both those provided by Amazon and published by third parties, CloudFormation returns <code>null</code>. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p>
    /// <p>To set the default version of an extension, use <code>SetTypeDefaultVersion</code>.</p>
    pub fn set_default_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.default_version_id = input;
        self
    }
    /// <p>The ID of the default version of the extension. The default version is used when the extension version isn't specified.</p>
    /// <p>This applies only to private extensions you have registered in your account. For public extensions, both those provided by Amazon and published by third parties, CloudFormation returns <code>null</code>. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p>
    /// <p>To set the default version of an extension, use <code>SetTypeDefaultVersion</code>.</p>
    pub fn get_default_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.default_version_id
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub fn type_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.type_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub fn set_type_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.type_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the extension.</p>
    pub fn get_type_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.type_arn
    }
    /// <p>When the specified extension version was registered. This applies only to:</p>
    /// <ul>
    /// <li>
    /// <p>Private extensions you have registered in your account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p></li>
    /// <li>
    /// <p>Public extensions you have activated in your account with auto-update specified. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a>.</p></li>
    /// </ul>
    /// <p>For all other extension types, CloudFormation returns <code>null</code>.</p>
    pub fn last_updated(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the specified extension version was registered. This applies only to:</p>
    /// <ul>
    /// <li>
    /// <p>Private extensions you have registered in your account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p></li>
    /// <li>
    /// <p>Public extensions you have activated in your account with auto-update specified. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a>.</p></li>
    /// </ul>
    /// <p>For all other extension types, CloudFormation returns <code>null</code>.</p>
    pub fn set_last_updated(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated = input;
        self
    }
    /// <p>When the specified extension version was registered. This applies only to:</p>
    /// <ul>
    /// <li>
    /// <p>Private extensions you have registered in your account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_RegisterType.html">RegisterType</a>.</p></li>
    /// <li>
    /// <p>Public extensions you have activated in your account with auto-update specified. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/API_ActivateType.html">ActivateType</a>.</p></li>
    /// </ul>
    /// <p>For all other extension types, CloudFormation returns <code>null</code>.</p>
    pub fn get_last_updated(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated
    }
    /// <p>The description of the extension.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the extension.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The description of the extension.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>The ID of the extension publisher, if the extension is published by a third party. Extensions published by Amazon don't return a publisher ID.</p>
    pub fn publisher_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.publisher_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the extension publisher, if the extension is published by a third party. Extensions published by Amazon don't return a publisher ID.</p>
    pub fn set_publisher_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.publisher_id = input;
        self
    }
    /// <p>The ID of the extension publisher, if the extension is published by a third party. Extensions published by Amazon don't return a publisher ID.</p>
    pub fn get_publisher_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.publisher_id
    }
    /// <p>For public extensions that have been activated for this account and Region, the type name of the public extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when enabling the extension in this account and Region, CloudFormation treats that alias as the extension's type name within the account and Region, not the type name of the public extension. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-alias">Use aliases to refer to extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn original_type_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.original_type_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For public extensions that have been activated for this account and Region, the type name of the public extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when enabling the extension in this account and Region, CloudFormation treats that alias as the extension's type name within the account and Region, not the type name of the public extension. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-alias">Use aliases to refer to extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn set_original_type_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.original_type_name = input;
        self
    }
    /// <p>For public extensions that have been activated for this account and Region, the type name of the public extension.</p>
    /// <p>If you specified a <code>TypeNameAlias</code> when enabling the extension in this account and Region, CloudFormation treats that alias as the extension's type name within the account and Region, not the type name of the public extension. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-alias">Use aliases to refer to extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn get_original_type_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.original_type_name
    }
    /// <p>For public extensions that have been activated for this account and Region, the version of the public extension to be used for CloudFormation operations in this account and Region.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn public_version_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.public_version_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For public extensions that have been activated for this account and Region, the version of the public extension to be used for CloudFormation operations in this account and Region.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn set_public_version_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.public_version_number = input;
        self
    }
    /// <p>For public extensions that have been activated for this account and Region, the version of the public extension to be used for CloudFormation operations in this account and Region.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn get_public_version_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.public_version_number
    }
    /// <p>For public extensions that have been activated for this account and Region, the latest version of the public extension <i>that is available</i>. For any extensions other than activated third-party extensions, CloudFormation returns <code>null</code>.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn latest_public_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.latest_public_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For public extensions that have been activated for this account and Region, the latest version of the public extension <i>that is available</i>. For any extensions other than activated third-party extensions, CloudFormation returns <code>null</code>.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn set_latest_public_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.latest_public_version = input;
        self
    }
    /// <p>For public extensions that have been activated for this account and Region, the latest version of the public extension <i>that is available</i>. For any extensions other than activated third-party extensions, CloudFormation returns <code>null</code>.</p>
    /// <p>How you specified <code>AutoUpdate</code> when enabling the extension affects whether CloudFormation automatically updates the extension in this account and Region when a new version is released. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/registry-public.html#registry-public-enable-auto">Automatically use new versions of extensions</a> in the <i>CloudFormation User Guide</i>.</p>
    pub fn get_latest_public_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.latest_public_version
    }
    /// <p>The service used to verify the publisher identity.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/publish-extension.html">Publishing extensions to make them available for public use</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub fn publisher_identity(mut self, input: crate::types::IdentityProvider) -> Self {
        self.publisher_identity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The service used to verify the publisher identity.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/publish-extension.html">Publishing extensions to make them available for public use</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub fn set_publisher_identity(mut self, input: ::std::option::Option<crate::types::IdentityProvider>) -> Self {
        self.publisher_identity = input;
        self
    }
    /// <p>The service used to verify the publisher identity.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/cloudformation-cli/latest/userguide/publish-extension.html">Publishing extensions to make them available for public use</a> in the <i>CloudFormation Command Line Interface (CLI) User Guide</i>.</p>
    pub fn get_publisher_identity(&self) -> &::std::option::Option<crate::types::IdentityProvider> {
        &self.publisher_identity
    }
    /// <p>The publisher name, as defined in the public profile for that publisher in the service used to verify the publisher identity.</p>
    pub fn publisher_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.publisher_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The publisher name, as defined in the public profile for that publisher in the service used to verify the publisher identity.</p>
    pub fn set_publisher_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.publisher_name = input;
        self
    }
    /// <p>The publisher name, as defined in the public profile for that publisher in the service used to verify the publisher identity.</p>
    pub fn get_publisher_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.publisher_name
    }
    /// <p>Whether the extension is activated for this account and Region.</p>
    /// <p>This applies only to third-party public extensions. Extensions published by Amazon are activated by default.</p>
    pub fn is_activated(mut self, input: bool) -> Self {
        self.is_activated = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the extension is activated for this account and Region.</p>
    /// <p>This applies only to third-party public extensions. Extensions published by Amazon are activated by default.</p>
    pub fn set_is_activated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_activated = input;
        self
    }
    /// <p>Whether the extension is activated for this account and Region.</p>
    /// <p>This applies only to third-party public extensions. Extensions published by Amazon are activated by default.</p>
    pub fn get_is_activated(&self) -> &::std::option::Option<bool> {
        &self.is_activated
    }
    /// Consumes the builder and constructs a [`TypeSummary`](crate::types::TypeSummary).
    pub fn build(self) -> crate::types::TypeSummary {
        crate::types::TypeSummary {
            r#type: self.r#type,
            type_name: self.type_name,
            default_version_id: self.default_version_id,
            type_arn: self.type_arn,
            last_updated: self.last_updated,
            description: self.description,
            publisher_id: self.publisher_id,
            original_type_name: self.original_type_name,
            public_version_number: self.public_version_number,
            latest_public_version: self.latest_public_version,
            publisher_identity: self.publisher_identity,
            publisher_name: self.publisher_name,
            is_activated: self.is_activated,
        }
    }
}
