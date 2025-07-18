// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RefreshTokenInput {
    /// <p>The third-party provider for the token. The only valid value is <code>figma</code>.</p>
    pub provider: ::std::option::Option<crate::types::TokenProviders>,
    /// <p>Information about the refresh token request.</p>
    pub refresh_token_body: ::std::option::Option<crate::types::RefreshTokenRequestBody>,
}
impl RefreshTokenInput {
    /// <p>The third-party provider for the token. The only valid value is <code>figma</code>.</p>
    pub fn provider(&self) -> ::std::option::Option<&crate::types::TokenProviders> {
        self.provider.as_ref()
    }
    /// <p>Information about the refresh token request.</p>
    pub fn refresh_token_body(&self) -> ::std::option::Option<&crate::types::RefreshTokenRequestBody> {
        self.refresh_token_body.as_ref()
    }
}
impl RefreshTokenInput {
    /// Creates a new builder-style object to manufacture [`RefreshTokenInput`](crate::operation::refresh_token::RefreshTokenInput).
    pub fn builder() -> crate::operation::refresh_token::builders::RefreshTokenInputBuilder {
        crate::operation::refresh_token::builders::RefreshTokenInputBuilder::default()
    }
}

/// A builder for [`RefreshTokenInput`](crate::operation::refresh_token::RefreshTokenInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RefreshTokenInputBuilder {
    pub(crate) provider: ::std::option::Option<crate::types::TokenProviders>,
    pub(crate) refresh_token_body: ::std::option::Option<crate::types::RefreshTokenRequestBody>,
}
impl RefreshTokenInputBuilder {
    /// <p>The third-party provider for the token. The only valid value is <code>figma</code>.</p>
    /// This field is required.
    pub fn provider(mut self, input: crate::types::TokenProviders) -> Self {
        self.provider = ::std::option::Option::Some(input);
        self
    }
    /// <p>The third-party provider for the token. The only valid value is <code>figma</code>.</p>
    pub fn set_provider(mut self, input: ::std::option::Option<crate::types::TokenProviders>) -> Self {
        self.provider = input;
        self
    }
    /// <p>The third-party provider for the token. The only valid value is <code>figma</code>.</p>
    pub fn get_provider(&self) -> &::std::option::Option<crate::types::TokenProviders> {
        &self.provider
    }
    /// <p>Information about the refresh token request.</p>
    /// This field is required.
    pub fn refresh_token_body(mut self, input: crate::types::RefreshTokenRequestBody) -> Self {
        self.refresh_token_body = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the refresh token request.</p>
    pub fn set_refresh_token_body(mut self, input: ::std::option::Option<crate::types::RefreshTokenRequestBody>) -> Self {
        self.refresh_token_body = input;
        self
    }
    /// <p>Information about the refresh token request.</p>
    pub fn get_refresh_token_body(&self) -> &::std::option::Option<crate::types::RefreshTokenRequestBody> {
        &self.refresh_token_body
    }
    /// Consumes the builder and constructs a [`RefreshTokenInput`](crate::operation::refresh_token::RefreshTokenInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::refresh_token::RefreshTokenInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::refresh_token::RefreshTokenInput {
            provider: self.provider,
            refresh_token_body: self.refresh_token_body,
        })
    }
}
