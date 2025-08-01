// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The IAM SAML identity provider used for federated authentication.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FederatedAuthenticationRequest {
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider.</p>
    pub saml_provider_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider for the self-service portal.</p>
    pub self_service_saml_provider_arn: ::std::option::Option<::std::string::String>,
}
impl FederatedAuthenticationRequest {
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider.</p>
    pub fn saml_provider_arn(&self) -> ::std::option::Option<&str> {
        self.saml_provider_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider for the self-service portal.</p>
    pub fn self_service_saml_provider_arn(&self) -> ::std::option::Option<&str> {
        self.self_service_saml_provider_arn.as_deref()
    }
}
impl FederatedAuthenticationRequest {
    /// Creates a new builder-style object to manufacture [`FederatedAuthenticationRequest`](crate::types::FederatedAuthenticationRequest).
    pub fn builder() -> crate::types::builders::FederatedAuthenticationRequestBuilder {
        crate::types::builders::FederatedAuthenticationRequestBuilder::default()
    }
}

/// A builder for [`FederatedAuthenticationRequest`](crate::types::FederatedAuthenticationRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FederatedAuthenticationRequestBuilder {
    pub(crate) saml_provider_arn: ::std::option::Option<::std::string::String>,
    pub(crate) self_service_saml_provider_arn: ::std::option::Option<::std::string::String>,
}
impl FederatedAuthenticationRequestBuilder {
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider.</p>
    pub fn saml_provider_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.saml_provider_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider.</p>
    pub fn set_saml_provider_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.saml_provider_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider.</p>
    pub fn get_saml_provider_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.saml_provider_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider for the self-service portal.</p>
    pub fn self_service_saml_provider_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.self_service_saml_provider_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider for the self-service portal.</p>
    pub fn set_self_service_saml_provider_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.self_service_saml_provider_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM SAML identity provider for the self-service portal.</p>
    pub fn get_self_service_saml_provider_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.self_service_saml_provider_arn
    }
    /// Consumes the builder and constructs a [`FederatedAuthenticationRequest`](crate::types::FederatedAuthenticationRequest).
    pub fn build(self) -> crate::types::FederatedAuthenticationRequest {
        crate::types::FederatedAuthenticationRequest {
            saml_provider_arn: self.saml_provider_arn,
            self_service_saml_provider_arn: self.self_service_saml_provider_arn,
        }
    }
}
