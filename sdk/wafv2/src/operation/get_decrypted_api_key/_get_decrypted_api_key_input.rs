// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDecryptedApiKeyInput {
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub scope: ::std::option::Option<crate::types::Scope>,
    /// <p>The encrypted API key.</p>
    pub api_key: ::std::option::Option<::std::string::String>,
}
impl GetDecryptedApiKeyInput {
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn scope(&self) -> ::std::option::Option<&crate::types::Scope> {
        self.scope.as_ref()
    }
    /// <p>The encrypted API key.</p>
    pub fn api_key(&self) -> ::std::option::Option<&str> {
        self.api_key.as_deref()
    }
}
impl GetDecryptedApiKeyInput {
    /// Creates a new builder-style object to manufacture [`GetDecryptedApiKeyInput`](crate::operation::get_decrypted_api_key::GetDecryptedApiKeyInput).
    pub fn builder() -> crate::operation::get_decrypted_api_key::builders::GetDecryptedApiKeyInputBuilder {
        crate::operation::get_decrypted_api_key::builders::GetDecryptedApiKeyInputBuilder::default()
    }
}

/// A builder for [`GetDecryptedApiKeyInput`](crate::operation::get_decrypted_api_key::GetDecryptedApiKeyInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDecryptedApiKeyInputBuilder {
    pub(crate) scope: ::std::option::Option<crate::types::Scope>,
    pub(crate) api_key: ::std::option::Option<::std::string::String>,
}
impl GetDecryptedApiKeyInputBuilder {
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    /// This field is required.
    pub fn scope(mut self, input: crate::types::Scope) -> Self {
        self.scope = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn set_scope(mut self, input: ::std::option::Option<crate::types::Scope>) -> Self {
        self.scope = input;
        self
    }
    /// <p>Specifies whether this is for a global resource type, such as a Amazon CloudFront distribution. For an Amplify application, use <code>CLOUDFRONT</code>.</p>
    /// <p>To work with CloudFront, you must also specify the Region US East (N. Virginia) as follows:</p>
    /// <ul>
    /// <li>
    /// <p>CLI - Specify the Region when you use the CloudFront scope: <code>--scope=CLOUDFRONT --region=us-east-1</code>.</p></li>
    /// <li>
    /// <p>API and SDKs - For all calls, use the Region endpoint us-east-1.</p></li>
    /// </ul>
    pub fn get_scope(&self) -> &::std::option::Option<crate::types::Scope> {
        &self.scope
    }
    /// <p>The encrypted API key.</p>
    /// This field is required.
    pub fn api_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.api_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The encrypted API key.</p>
    pub fn set_api_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.api_key = input;
        self
    }
    /// <p>The encrypted API key.</p>
    pub fn get_api_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.api_key
    }
    /// Consumes the builder and constructs a [`GetDecryptedApiKeyInput`](crate::operation::get_decrypted_api_key::GetDecryptedApiKeyInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_decrypted_api_key::GetDecryptedApiKeyInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_decrypted_api_key::GetDecryptedApiKeyInput {
            scope: self.scope,
            api_key: self.api_key,
        })
    }
}
