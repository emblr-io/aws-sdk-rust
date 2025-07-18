// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes IAM Identity Center options for an OpenSearch Serverless security configuration in the form of a key-value map.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IamIdentityCenterConfigOptions {
    /// <p>The ARN of the IAM Identity Center instance used to integrate with OpenSearch Serverless.</p>
    pub instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub application_name: ::std::option::Option<::std::string::String>,
    /// <p>The description of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub application_description: ::std::option::Option<::std::string::String>,
    /// <p>The user attribute for this IAM Identity Center integration. Defaults to <code>UserId</code></p>
    pub user_attribute: ::std::option::Option<crate::types::IamIdentityCenterUserAttribute>,
    /// <p>The group attribute for this IAM Identity Center integration. Defaults to <code>GroupId</code>.</p>
    pub group_attribute: ::std::option::Option<crate::types::IamIdentityCenterGroupAttribute>,
}
impl IamIdentityCenterConfigOptions {
    /// <p>The ARN of the IAM Identity Center instance used to integrate with OpenSearch Serverless.</p>
    pub fn instance_arn(&self) -> ::std::option::Option<&str> {
        self.instance_arn.as_deref()
    }
    /// <p>The ARN of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
    /// <p>The name of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn application_name(&self) -> ::std::option::Option<&str> {
        self.application_name.as_deref()
    }
    /// <p>The description of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn application_description(&self) -> ::std::option::Option<&str> {
        self.application_description.as_deref()
    }
    /// <p>The user attribute for this IAM Identity Center integration. Defaults to <code>UserId</code></p>
    pub fn user_attribute(&self) -> ::std::option::Option<&crate::types::IamIdentityCenterUserAttribute> {
        self.user_attribute.as_ref()
    }
    /// <p>The group attribute for this IAM Identity Center integration. Defaults to <code>GroupId</code>.</p>
    pub fn group_attribute(&self) -> ::std::option::Option<&crate::types::IamIdentityCenterGroupAttribute> {
        self.group_attribute.as_ref()
    }
}
impl IamIdentityCenterConfigOptions {
    /// Creates a new builder-style object to manufacture [`IamIdentityCenterConfigOptions`](crate::types::IamIdentityCenterConfigOptions).
    pub fn builder() -> crate::types::builders::IamIdentityCenterConfigOptionsBuilder {
        crate::types::builders::IamIdentityCenterConfigOptionsBuilder::default()
    }
}

/// A builder for [`IamIdentityCenterConfigOptions`](crate::types::IamIdentityCenterConfigOptions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IamIdentityCenterConfigOptionsBuilder {
    pub(crate) instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) application_name: ::std::option::Option<::std::string::String>,
    pub(crate) application_description: ::std::option::Option<::std::string::String>,
    pub(crate) user_attribute: ::std::option::Option<crate::types::IamIdentityCenterUserAttribute>,
    pub(crate) group_attribute: ::std::option::Option<crate::types::IamIdentityCenterGroupAttribute>,
}
impl IamIdentityCenterConfigOptionsBuilder {
    /// <p>The ARN of the IAM Identity Center instance used to integrate with OpenSearch Serverless.</p>
    pub fn instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM Identity Center instance used to integrate with OpenSearch Serverless.</p>
    pub fn set_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_arn = input;
        self
    }
    /// <p>The ARN of the IAM Identity Center instance used to integrate with OpenSearch Serverless.</p>
    pub fn get_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_arn
    }
    /// <p>The ARN of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>The ARN of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// <p>The name of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn set_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_name = input;
        self
    }
    /// <p>The name of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn get_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_name
    }
    /// <p>The description of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn application_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn set_application_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_description = input;
        self
    }
    /// <p>The description of the IAM Identity Center application used to integrate with OpenSearch Serverless.</p>
    pub fn get_application_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_description
    }
    /// <p>The user attribute for this IAM Identity Center integration. Defaults to <code>UserId</code></p>
    pub fn user_attribute(mut self, input: crate::types::IamIdentityCenterUserAttribute) -> Self {
        self.user_attribute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The user attribute for this IAM Identity Center integration. Defaults to <code>UserId</code></p>
    pub fn set_user_attribute(mut self, input: ::std::option::Option<crate::types::IamIdentityCenterUserAttribute>) -> Self {
        self.user_attribute = input;
        self
    }
    /// <p>The user attribute for this IAM Identity Center integration. Defaults to <code>UserId</code></p>
    pub fn get_user_attribute(&self) -> &::std::option::Option<crate::types::IamIdentityCenterUserAttribute> {
        &self.user_attribute
    }
    /// <p>The group attribute for this IAM Identity Center integration. Defaults to <code>GroupId</code>.</p>
    pub fn group_attribute(mut self, input: crate::types::IamIdentityCenterGroupAttribute) -> Self {
        self.group_attribute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The group attribute for this IAM Identity Center integration. Defaults to <code>GroupId</code>.</p>
    pub fn set_group_attribute(mut self, input: ::std::option::Option<crate::types::IamIdentityCenterGroupAttribute>) -> Self {
        self.group_attribute = input;
        self
    }
    /// <p>The group attribute for this IAM Identity Center integration. Defaults to <code>GroupId</code>.</p>
    pub fn get_group_attribute(&self) -> &::std::option::Option<crate::types::IamIdentityCenterGroupAttribute> {
        &self.group_attribute
    }
    /// Consumes the builder and constructs a [`IamIdentityCenterConfigOptions`](crate::types::IamIdentityCenterConfigOptions).
    pub fn build(self) -> crate::types::IamIdentityCenterConfigOptions {
        crate::types::IamIdentityCenterConfigOptions {
            instance_arn: self.instance_arn,
            application_arn: self.application_arn,
            application_name: self.application_name,
            application_description: self.application_description,
            user_attribute: self.user_attribute,
            group_attribute: self.group_attribute,
        }
    }
}
