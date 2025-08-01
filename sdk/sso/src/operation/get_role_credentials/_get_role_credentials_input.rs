// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GetRoleCredentialsInput {
    /// <p>The friendly name of the role that is assigned to the user.</p>
    pub role_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the AWS account that is assigned to the user.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The token issued by the <code>CreateToken</code> API call. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateToken.html">CreateToken</a> in the <i>IAM Identity Center OIDC API Reference Guide</i>.</p>
    pub access_token: ::std::option::Option<::std::string::String>,
}
impl GetRoleCredentialsInput {
    /// <p>The friendly name of the role that is assigned to the user.</p>
    pub fn role_name(&self) -> ::std::option::Option<&str> {
        self.role_name.as_deref()
    }
    /// <p>The identifier for the AWS account that is assigned to the user.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The token issued by the <code>CreateToken</code> API call. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateToken.html">CreateToken</a> in the <i>IAM Identity Center OIDC API Reference Guide</i>.</p>
    pub fn access_token(&self) -> ::std::option::Option<&str> {
        self.access_token.as_deref()
    }
}
impl ::std::fmt::Debug for GetRoleCredentialsInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetRoleCredentialsInput");
        formatter.field("role_name", &self.role_name);
        formatter.field("account_id", &self.account_id);
        formatter.field("access_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl GetRoleCredentialsInput {
    /// Creates a new builder-style object to manufacture [`GetRoleCredentialsInput`](crate::operation::get_role_credentials::GetRoleCredentialsInput).
    pub fn builder() -> crate::operation::get_role_credentials::builders::GetRoleCredentialsInputBuilder {
        crate::operation::get_role_credentials::builders::GetRoleCredentialsInputBuilder::default()
    }
}

/// A builder for [`GetRoleCredentialsInput`](crate::operation::get_role_credentials::GetRoleCredentialsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GetRoleCredentialsInputBuilder {
    pub(crate) role_name: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) access_token: ::std::option::Option<::std::string::String>,
}
impl GetRoleCredentialsInputBuilder {
    /// <p>The friendly name of the role that is assigned to the user.</p>
    /// This field is required.
    pub fn role_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The friendly name of the role that is assigned to the user.</p>
    pub fn set_role_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_name = input;
        self
    }
    /// <p>The friendly name of the role that is assigned to the user.</p>
    pub fn get_role_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_name
    }
    /// <p>The identifier for the AWS account that is assigned to the user.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the AWS account that is assigned to the user.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The identifier for the AWS account that is assigned to the user.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The token issued by the <code>CreateToken</code> API call. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateToken.html">CreateToken</a> in the <i>IAM Identity Center OIDC API Reference Guide</i>.</p>
    /// This field is required.
    pub fn access_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token issued by the <code>CreateToken</code> API call. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateToken.html">CreateToken</a> in the <i>IAM Identity Center OIDC API Reference Guide</i>.</p>
    pub fn set_access_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_token = input;
        self
    }
    /// <p>The token issued by the <code>CreateToken</code> API call. For more information, see <a href="https://docs.aws.amazon.com/singlesignon/latest/OIDCAPIReference/API_CreateToken.html">CreateToken</a> in the <i>IAM Identity Center OIDC API Reference Guide</i>.</p>
    pub fn get_access_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_token
    }
    /// Consumes the builder and constructs a [`GetRoleCredentialsInput`](crate::operation::get_role_credentials::GetRoleCredentialsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_role_credentials::GetRoleCredentialsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_role_credentials::GetRoleCredentialsInput {
            role_name: self.role_name,
            account_id: self.account_id,
            access_token: self.access_token,
        })
    }
}
impl ::std::fmt::Debug for GetRoleCredentialsInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GetRoleCredentialsInputBuilder");
        formatter.field("role_name", &self.role_name);
        formatter.field("account_id", &self.account_id);
        formatter.field("access_token", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
