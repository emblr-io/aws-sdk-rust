// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTokenInput {
    /// <p>Amazon Resource Name (ARN) of the license. The ARN is mapped to the aud claim of the JWT token.</p>
    pub license_arn: ::std::option::Option<::std::string::String>,
    /// <p>Amazon Resource Name (ARN) of the IAM roles to embed in the token. License Manager does not check whether the roles are in use.</p>
    pub role_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Token expiration, in days, counted from token creation. The default is 365 days.</p>
    pub expiration_in_days: ::std::option::Option<i32>,
    /// <p>Data specified by the caller to be included in the JWT token. The data is mapped to the amr claim of the JWT token.</p>
    pub token_properties: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Idempotency token, valid for 10 minutes.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
}
impl CreateTokenInput {
    /// <p>Amazon Resource Name (ARN) of the license. The ARN is mapped to the aud claim of the JWT token.</p>
    pub fn license_arn(&self) -> ::std::option::Option<&str> {
        self.license_arn.as_deref()
    }
    /// <p>Amazon Resource Name (ARN) of the IAM roles to embed in the token. License Manager does not check whether the roles are in use.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.role_arns.is_none()`.
    pub fn role_arns(&self) -> &[::std::string::String] {
        self.role_arns.as_deref().unwrap_or_default()
    }
    /// <p>Token expiration, in days, counted from token creation. The default is 365 days.</p>
    pub fn expiration_in_days(&self) -> ::std::option::Option<i32> {
        self.expiration_in_days
    }
    /// <p>Data specified by the caller to be included in the JWT token. The data is mapped to the amr claim of the JWT token.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.token_properties.is_none()`.
    pub fn token_properties(&self) -> &[::std::string::String] {
        self.token_properties.as_deref().unwrap_or_default()
    }
    /// <p>Idempotency token, valid for 10 minutes.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
}
impl CreateTokenInput {
    /// Creates a new builder-style object to manufacture [`CreateTokenInput`](crate::operation::create_token::CreateTokenInput).
    pub fn builder() -> crate::operation::create_token::builders::CreateTokenInputBuilder {
        crate::operation::create_token::builders::CreateTokenInputBuilder::default()
    }
}

/// A builder for [`CreateTokenInput`](crate::operation::create_token::CreateTokenInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTokenInputBuilder {
    pub(crate) license_arn: ::std::option::Option<::std::string::String>,
    pub(crate) role_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) expiration_in_days: ::std::option::Option<i32>,
    pub(crate) token_properties: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
}
impl CreateTokenInputBuilder {
    /// <p>Amazon Resource Name (ARN) of the license. The ARN is mapped to the aud claim of the JWT token.</p>
    /// This field is required.
    pub fn license_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the license. The ARN is mapped to the aud claim of the JWT token.</p>
    pub fn set_license_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the license. The ARN is mapped to the aud claim of the JWT token.</p>
    pub fn get_license_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_arn
    }
    /// Appends an item to `role_arns`.
    ///
    /// To override the contents of this collection use [`set_role_arns`](Self::set_role_arns).
    ///
    /// <p>Amazon Resource Name (ARN) of the IAM roles to embed in the token. License Manager does not check whether the roles are in use.</p>
    pub fn role_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.role_arns.unwrap_or_default();
        v.push(input.into());
        self.role_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>Amazon Resource Name (ARN) of the IAM roles to embed in the token. License Manager does not check whether the roles are in use.</p>
    pub fn set_role_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.role_arns = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the IAM roles to embed in the token. License Manager does not check whether the roles are in use.</p>
    pub fn get_role_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.role_arns
    }
    /// <p>Token expiration, in days, counted from token creation. The default is 365 days.</p>
    pub fn expiration_in_days(mut self, input: i32) -> Self {
        self.expiration_in_days = ::std::option::Option::Some(input);
        self
    }
    /// <p>Token expiration, in days, counted from token creation. The default is 365 days.</p>
    pub fn set_expiration_in_days(mut self, input: ::std::option::Option<i32>) -> Self {
        self.expiration_in_days = input;
        self
    }
    /// <p>Token expiration, in days, counted from token creation. The default is 365 days.</p>
    pub fn get_expiration_in_days(&self) -> &::std::option::Option<i32> {
        &self.expiration_in_days
    }
    /// Appends an item to `token_properties`.
    ///
    /// To override the contents of this collection use [`set_token_properties`](Self::set_token_properties).
    ///
    /// <p>Data specified by the caller to be included in the JWT token. The data is mapped to the amr claim of the JWT token.</p>
    pub fn token_properties(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.token_properties.unwrap_or_default();
        v.push(input.into());
        self.token_properties = ::std::option::Option::Some(v);
        self
    }
    /// <p>Data specified by the caller to be included in the JWT token. The data is mapped to the amr claim of the JWT token.</p>
    pub fn set_token_properties(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.token_properties = input;
        self
    }
    /// <p>Data specified by the caller to be included in the JWT token. The data is mapped to the amr claim of the JWT token.</p>
    pub fn get_token_properties(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.token_properties
    }
    /// <p>Idempotency token, valid for 10 minutes.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Idempotency token, valid for 10 minutes.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Idempotency token, valid for 10 minutes.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Consumes the builder and constructs a [`CreateTokenInput`](crate::operation::create_token::CreateTokenInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_token::CreateTokenInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_token::CreateTokenInput {
            license_arn: self.license_arn,
            role_arns: self.role_arns,
            expiration_in_days: self.expiration_in_days,
            token_properties: self.token_properties,
            client_token: self.client_token,
        })
    }
}
