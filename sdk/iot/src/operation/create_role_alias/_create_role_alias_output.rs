// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateRoleAliasOutput {
    /// <p>The role alias.</p>
    pub role_alias: ::std::option::Option<::std::string::String>,
    /// <p>The role alias ARN.</p>
    pub role_alias_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateRoleAliasOutput {
    /// <p>The role alias.</p>
    pub fn role_alias(&self) -> ::std::option::Option<&str> {
        self.role_alias.as_deref()
    }
    /// <p>The role alias ARN.</p>
    pub fn role_alias_arn(&self) -> ::std::option::Option<&str> {
        self.role_alias_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateRoleAliasOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateRoleAliasOutput {
    /// Creates a new builder-style object to manufacture [`CreateRoleAliasOutput`](crate::operation::create_role_alias::CreateRoleAliasOutput).
    pub fn builder() -> crate::operation::create_role_alias::builders::CreateRoleAliasOutputBuilder {
        crate::operation::create_role_alias::builders::CreateRoleAliasOutputBuilder::default()
    }
}

/// A builder for [`CreateRoleAliasOutput`](crate::operation::create_role_alias::CreateRoleAliasOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateRoleAliasOutputBuilder {
    pub(crate) role_alias: ::std::option::Option<::std::string::String>,
    pub(crate) role_alias_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateRoleAliasOutputBuilder {
    /// <p>The role alias.</p>
    pub fn role_alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The role alias.</p>
    pub fn set_role_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_alias = input;
        self
    }
    /// <p>The role alias.</p>
    pub fn get_role_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_alias
    }
    /// <p>The role alias ARN.</p>
    pub fn role_alias_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_alias_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The role alias ARN.</p>
    pub fn set_role_alias_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_alias_arn = input;
        self
    }
    /// <p>The role alias ARN.</p>
    pub fn get_role_alias_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_alias_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateRoleAliasOutput`](crate::operation::create_role_alias::CreateRoleAliasOutput).
    pub fn build(self) -> crate::operation::create_role_alias::CreateRoleAliasOutput {
        crate::operation::create_role_alias::CreateRoleAliasOutput {
            role_alias: self.role_alias,
            role_alias_arn: self.role_alias_arn,
            _request_id: self._request_id,
        }
    }
}
