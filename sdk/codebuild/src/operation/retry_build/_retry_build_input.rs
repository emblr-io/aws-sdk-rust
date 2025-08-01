// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RetryBuildInput {
    /// <p>Specifies the identifier of the build to restart.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A unique, case sensitive identifier you provide to ensure the idempotency of the <code>RetryBuild</code> request. The token is included in the <code>RetryBuild</code> request and is valid for five minutes. If you repeat the <code>RetryBuild</code> request with the same token, but change a parameter, CodeBuild returns a parameter mismatch error.</p>
    pub idempotency_token: ::std::option::Option<::std::string::String>,
}
impl RetryBuildInput {
    /// <p>Specifies the identifier of the build to restart.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A unique, case sensitive identifier you provide to ensure the idempotency of the <code>RetryBuild</code> request. The token is included in the <code>RetryBuild</code> request and is valid for five minutes. If you repeat the <code>RetryBuild</code> request with the same token, but change a parameter, CodeBuild returns a parameter mismatch error.</p>
    pub fn idempotency_token(&self) -> ::std::option::Option<&str> {
        self.idempotency_token.as_deref()
    }
}
impl RetryBuildInput {
    /// Creates a new builder-style object to manufacture [`RetryBuildInput`](crate::operation::retry_build::RetryBuildInput).
    pub fn builder() -> crate::operation::retry_build::builders::RetryBuildInputBuilder {
        crate::operation::retry_build::builders::RetryBuildInputBuilder::default()
    }
}

/// A builder for [`RetryBuildInput`](crate::operation::retry_build::RetryBuildInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RetryBuildInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) idempotency_token: ::std::option::Option<::std::string::String>,
}
impl RetryBuildInputBuilder {
    /// <p>Specifies the identifier of the build to restart.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the identifier of the build to restart.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>Specifies the identifier of the build to restart.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A unique, case sensitive identifier you provide to ensure the idempotency of the <code>RetryBuild</code> request. The token is included in the <code>RetryBuild</code> request and is valid for five minutes. If you repeat the <code>RetryBuild</code> request with the same token, but change a parameter, CodeBuild returns a parameter mismatch error.</p>
    pub fn idempotency_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.idempotency_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case sensitive identifier you provide to ensure the idempotency of the <code>RetryBuild</code> request. The token is included in the <code>RetryBuild</code> request and is valid for five minutes. If you repeat the <code>RetryBuild</code> request with the same token, but change a parameter, CodeBuild returns a parameter mismatch error.</p>
    pub fn set_idempotency_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.idempotency_token = input;
        self
    }
    /// <p>A unique, case sensitive identifier you provide to ensure the idempotency of the <code>RetryBuild</code> request. The token is included in the <code>RetryBuild</code> request and is valid for five minutes. If you repeat the <code>RetryBuild</code> request with the same token, but change a parameter, CodeBuild returns a parameter mismatch error.</p>
    pub fn get_idempotency_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.idempotency_token
    }
    /// Consumes the builder and constructs a [`RetryBuildInput`](crate::operation::retry_build::RetryBuildInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::retry_build::RetryBuildInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::retry_build::RetryBuildInput {
            id: self.id,
            idempotency_token: self.idempotency_token,
        })
    }
}
