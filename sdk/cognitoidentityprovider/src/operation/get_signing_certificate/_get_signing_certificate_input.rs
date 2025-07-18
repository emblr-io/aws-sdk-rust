// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to get a signing certificate from Amazon Cognito.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSigningCertificateInput {
    /// <p>The ID of the user pool where you want to view the signing certificate.</p>
    pub user_pool_id: ::std::option::Option<::std::string::String>,
}
impl GetSigningCertificateInput {
    /// <p>The ID of the user pool where you want to view the signing certificate.</p>
    pub fn user_pool_id(&self) -> ::std::option::Option<&str> {
        self.user_pool_id.as_deref()
    }
}
impl GetSigningCertificateInput {
    /// Creates a new builder-style object to manufacture [`GetSigningCertificateInput`](crate::operation::get_signing_certificate::GetSigningCertificateInput).
    pub fn builder() -> crate::operation::get_signing_certificate::builders::GetSigningCertificateInputBuilder {
        crate::operation::get_signing_certificate::builders::GetSigningCertificateInputBuilder::default()
    }
}

/// A builder for [`GetSigningCertificateInput`](crate::operation::get_signing_certificate::GetSigningCertificateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSigningCertificateInputBuilder {
    pub(crate) user_pool_id: ::std::option::Option<::std::string::String>,
}
impl GetSigningCertificateInputBuilder {
    /// <p>The ID of the user pool where you want to view the signing certificate.</p>
    /// This field is required.
    pub fn user_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the user pool where you want to view the signing certificate.</p>
    pub fn set_user_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_id = input;
        self
    }
    /// <p>The ID of the user pool where you want to view the signing certificate.</p>
    pub fn get_user_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_id
    }
    /// Consumes the builder and constructs a [`GetSigningCertificateInput`](crate::operation::get_signing_certificate::GetSigningCertificateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_signing_certificate::GetSigningCertificateInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_signing_certificate::GetSigningCertificateInput {
            user_pool_id: self.user_pool_id,
        })
    }
}
