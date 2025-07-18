// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAliasInput {
    /// <p>A friendly name that you can use to refer to a key. An alias must begin with <code>alias/</code> followed by a name, for example <code>alias/ExampleAlias</code>. It can contain only alphanumeric characters, forward slashes (/), underscores (_), and dashes (-).</p><important>
    /// <p>Don't include personal, confidential or sensitive information in this field. This field may be displayed in plaintext in CloudTrail logs and other output.</p>
    /// </important>
    pub alias_name: ::std::option::Option<::std::string::String>,
    /// <p>The <code>KeyARN</code> of the key to associate with the alias.</p>
    pub key_arn: ::std::option::Option<::std::string::String>,
}
impl CreateAliasInput {
    /// <p>A friendly name that you can use to refer to a key. An alias must begin with <code>alias/</code> followed by a name, for example <code>alias/ExampleAlias</code>. It can contain only alphanumeric characters, forward slashes (/), underscores (_), and dashes (-).</p><important>
    /// <p>Don't include personal, confidential or sensitive information in this field. This field may be displayed in plaintext in CloudTrail logs and other output.</p>
    /// </important>
    pub fn alias_name(&self) -> ::std::option::Option<&str> {
        self.alias_name.as_deref()
    }
    /// <p>The <code>KeyARN</code> of the key to associate with the alias.</p>
    pub fn key_arn(&self) -> ::std::option::Option<&str> {
        self.key_arn.as_deref()
    }
}
impl CreateAliasInput {
    /// Creates a new builder-style object to manufacture [`CreateAliasInput`](crate::operation::create_alias::CreateAliasInput).
    pub fn builder() -> crate::operation::create_alias::builders::CreateAliasInputBuilder {
        crate::operation::create_alias::builders::CreateAliasInputBuilder::default()
    }
}

/// A builder for [`CreateAliasInput`](crate::operation::create_alias::CreateAliasInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAliasInputBuilder {
    pub(crate) alias_name: ::std::option::Option<::std::string::String>,
    pub(crate) key_arn: ::std::option::Option<::std::string::String>,
}
impl CreateAliasInputBuilder {
    /// <p>A friendly name that you can use to refer to a key. An alias must begin with <code>alias/</code> followed by a name, for example <code>alias/ExampleAlias</code>. It can contain only alphanumeric characters, forward slashes (/), underscores (_), and dashes (-).</p><important>
    /// <p>Don't include personal, confidential or sensitive information in this field. This field may be displayed in plaintext in CloudTrail logs and other output.</p>
    /// </important>
    /// This field is required.
    pub fn alias_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A friendly name that you can use to refer to a key. An alias must begin with <code>alias/</code> followed by a name, for example <code>alias/ExampleAlias</code>. It can contain only alphanumeric characters, forward slashes (/), underscores (_), and dashes (-).</p><important>
    /// <p>Don't include personal, confidential or sensitive information in this field. This field may be displayed in plaintext in CloudTrail logs and other output.</p>
    /// </important>
    pub fn set_alias_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias_name = input;
        self
    }
    /// <p>A friendly name that you can use to refer to a key. An alias must begin with <code>alias/</code> followed by a name, for example <code>alias/ExampleAlias</code>. It can contain only alphanumeric characters, forward slashes (/), underscores (_), and dashes (-).</p><important>
    /// <p>Don't include personal, confidential or sensitive information in this field. This field may be displayed in plaintext in CloudTrail logs and other output.</p>
    /// </important>
    pub fn get_alias_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias_name
    }
    /// <p>The <code>KeyARN</code> of the key to associate with the alias.</p>
    pub fn key_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>KeyARN</code> of the key to associate with the alias.</p>
    pub fn set_key_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_arn = input;
        self
    }
    /// <p>The <code>KeyARN</code> of the key to associate with the alias.</p>
    pub fn get_key_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_arn
    }
    /// Consumes the builder and constructs a [`CreateAliasInput`](crate::operation::create_alias::CreateAliasInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_alias::CreateAliasInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_alias::CreateAliasInput {
            alias_name: self.alias_name,
            key_arn: self.key_arn,
        })
    }
}
