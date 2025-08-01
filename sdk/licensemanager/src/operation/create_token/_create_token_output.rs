// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTokenOutput {
    /// <p>Token ID.</p>
    pub token_id: ::std::option::Option<::std::string::String>,
    /// <p>Token type.</p>
    pub token_type: ::std::option::Option<crate::types::TokenType>,
    /// <p>Refresh token, encoded as a JWT token.</p>
    pub token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTokenOutput {
    /// <p>Token ID.</p>
    pub fn token_id(&self) -> ::std::option::Option<&str> {
        self.token_id.as_deref()
    }
    /// <p>Token type.</p>
    pub fn token_type(&self) -> ::std::option::Option<&crate::types::TokenType> {
        self.token_type.as_ref()
    }
    /// <p>Refresh token, encoded as a JWT token.</p>
    pub fn token(&self) -> ::std::option::Option<&str> {
        self.token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateTokenOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateTokenOutput {
    /// Creates a new builder-style object to manufacture [`CreateTokenOutput`](crate::operation::create_token::CreateTokenOutput).
    pub fn builder() -> crate::operation::create_token::builders::CreateTokenOutputBuilder {
        crate::operation::create_token::builders::CreateTokenOutputBuilder::default()
    }
}

/// A builder for [`CreateTokenOutput`](crate::operation::create_token::CreateTokenOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTokenOutputBuilder {
    pub(crate) token_id: ::std::option::Option<::std::string::String>,
    pub(crate) token_type: ::std::option::Option<crate::types::TokenType>,
    pub(crate) token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateTokenOutputBuilder {
    /// <p>Token ID.</p>
    pub fn token_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Token ID.</p>
    pub fn set_token_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token_id = input;
        self
    }
    /// <p>Token ID.</p>
    pub fn get_token_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.token_id
    }
    /// <p>Token type.</p>
    pub fn token_type(mut self, input: crate::types::TokenType) -> Self {
        self.token_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Token type.</p>
    pub fn set_token_type(mut self, input: ::std::option::Option<crate::types::TokenType>) -> Self {
        self.token_type = input;
        self
    }
    /// <p>Token type.</p>
    pub fn get_token_type(&self) -> &::std::option::Option<crate::types::TokenType> {
        &self.token_type
    }
    /// <p>Refresh token, encoded as a JWT token.</p>
    pub fn token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Refresh token, encoded as a JWT token.</p>
    pub fn set_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token = input;
        self
    }
    /// <p>Refresh token, encoded as a JWT token.</p>
    pub fn get_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateTokenOutput`](crate::operation::create_token::CreateTokenOutput).
    pub fn build(self) -> crate::operation::create_token::CreateTokenOutput {
        crate::operation::create_token::CreateTokenOutput {
            token_id: self.token_id,
            token_type: self.token_type,
            token: self.token,
            _request_id: self._request_id,
        }
    }
}
