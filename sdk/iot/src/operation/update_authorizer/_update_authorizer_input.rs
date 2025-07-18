// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAuthorizerInput {
    /// <p>The authorizer name.</p>
    pub authorizer_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the authorizer's Lambda function.</p>
    pub authorizer_function_arn: ::std::option::Option<::std::string::String>,
    /// <p>The key used to extract the token from the HTTP headers.</p>
    pub token_key_name: ::std::option::Option<::std::string::String>,
    /// <p>The public keys used to verify the token signature.</p>
    pub token_signing_public_keys: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>The status of the update authorizer request.</p>
    pub status: ::std::option::Option<crate::types::AuthorizerStatus>,
    /// <p>When <code>true</code>, the result from the authorizer’s Lambda function is cached for the time specified in <code>refreshAfterInSeconds</code>. The cached result is used while the device reuses the same HTTP connection.</p>
    pub enable_caching_for_http: ::std::option::Option<bool>,
}
impl UpdateAuthorizerInput {
    /// <p>The authorizer name.</p>
    pub fn authorizer_name(&self) -> ::std::option::Option<&str> {
        self.authorizer_name.as_deref()
    }
    /// <p>The ARN of the authorizer's Lambda function.</p>
    pub fn authorizer_function_arn(&self) -> ::std::option::Option<&str> {
        self.authorizer_function_arn.as_deref()
    }
    /// <p>The key used to extract the token from the HTTP headers.</p>
    pub fn token_key_name(&self) -> ::std::option::Option<&str> {
        self.token_key_name.as_deref()
    }
    /// <p>The public keys used to verify the token signature.</p>
    pub fn token_signing_public_keys(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.token_signing_public_keys.as_ref()
    }
    /// <p>The status of the update authorizer request.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::AuthorizerStatus> {
        self.status.as_ref()
    }
    /// <p>When <code>true</code>, the result from the authorizer’s Lambda function is cached for the time specified in <code>refreshAfterInSeconds</code>. The cached result is used while the device reuses the same HTTP connection.</p>
    pub fn enable_caching_for_http(&self) -> ::std::option::Option<bool> {
        self.enable_caching_for_http
    }
}
impl UpdateAuthorizerInput {
    /// Creates a new builder-style object to manufacture [`UpdateAuthorizerInput`](crate::operation::update_authorizer::UpdateAuthorizerInput).
    pub fn builder() -> crate::operation::update_authorizer::builders::UpdateAuthorizerInputBuilder {
        crate::operation::update_authorizer::builders::UpdateAuthorizerInputBuilder::default()
    }
}

/// A builder for [`UpdateAuthorizerInput`](crate::operation::update_authorizer::UpdateAuthorizerInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAuthorizerInputBuilder {
    pub(crate) authorizer_name: ::std::option::Option<::std::string::String>,
    pub(crate) authorizer_function_arn: ::std::option::Option<::std::string::String>,
    pub(crate) token_key_name: ::std::option::Option<::std::string::String>,
    pub(crate) token_signing_public_keys: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) status: ::std::option::Option<crate::types::AuthorizerStatus>,
    pub(crate) enable_caching_for_http: ::std::option::Option<bool>,
}
impl UpdateAuthorizerInputBuilder {
    /// <p>The authorizer name.</p>
    /// This field is required.
    pub fn authorizer_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authorizer_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The authorizer name.</p>
    pub fn set_authorizer_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authorizer_name = input;
        self
    }
    /// <p>The authorizer name.</p>
    pub fn get_authorizer_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.authorizer_name
    }
    /// <p>The ARN of the authorizer's Lambda function.</p>
    pub fn authorizer_function_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authorizer_function_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the authorizer's Lambda function.</p>
    pub fn set_authorizer_function_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authorizer_function_arn = input;
        self
    }
    /// <p>The ARN of the authorizer's Lambda function.</p>
    pub fn get_authorizer_function_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.authorizer_function_arn
    }
    /// <p>The key used to extract the token from the HTTP headers.</p>
    pub fn token_key_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.token_key_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key used to extract the token from the HTTP headers.</p>
    pub fn set_token_key_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.token_key_name = input;
        self
    }
    /// <p>The key used to extract the token from the HTTP headers.</p>
    pub fn get_token_key_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.token_key_name
    }
    /// Adds a key-value pair to `token_signing_public_keys`.
    ///
    /// To override the contents of this collection use [`set_token_signing_public_keys`](Self::set_token_signing_public_keys).
    ///
    /// <p>The public keys used to verify the token signature.</p>
    pub fn token_signing_public_keys(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.token_signing_public_keys.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.token_signing_public_keys = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The public keys used to verify the token signature.</p>
    pub fn set_token_signing_public_keys(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.token_signing_public_keys = input;
        self
    }
    /// <p>The public keys used to verify the token signature.</p>
    pub fn get_token_signing_public_keys(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.token_signing_public_keys
    }
    /// <p>The status of the update authorizer request.</p>
    pub fn status(mut self, input: crate::types::AuthorizerStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the update authorizer request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::AuthorizerStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the update authorizer request.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::AuthorizerStatus> {
        &self.status
    }
    /// <p>When <code>true</code>, the result from the authorizer’s Lambda function is cached for the time specified in <code>refreshAfterInSeconds</code>. The cached result is used while the device reuses the same HTTP connection.</p>
    pub fn enable_caching_for_http(mut self, input: bool) -> Self {
        self.enable_caching_for_http = ::std::option::Option::Some(input);
        self
    }
    /// <p>When <code>true</code>, the result from the authorizer’s Lambda function is cached for the time specified in <code>refreshAfterInSeconds</code>. The cached result is used while the device reuses the same HTTP connection.</p>
    pub fn set_enable_caching_for_http(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_caching_for_http = input;
        self
    }
    /// <p>When <code>true</code>, the result from the authorizer’s Lambda function is cached for the time specified in <code>refreshAfterInSeconds</code>. The cached result is used while the device reuses the same HTTP connection.</p>
    pub fn get_enable_caching_for_http(&self) -> &::std::option::Option<bool> {
        &self.enable_caching_for_http
    }
    /// Consumes the builder and constructs a [`UpdateAuthorizerInput`](crate::operation::update_authorizer::UpdateAuthorizerInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_authorizer::UpdateAuthorizerInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_authorizer::UpdateAuthorizerInput {
            authorizer_name: self.authorizer_name,
            authorizer_function_arn: self.authorizer_function_arn,
            token_key_name: self.token_key_name,
            token_signing_public_keys: self.token_signing_public_keys,
            status: self.status,
            enable_caching_for_http: self.enable_caching_for_http,
        })
    }
}
