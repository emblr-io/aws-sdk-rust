// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateIdentityProviderConfigInput {
    /// <p>The name of your cluster.</p>
    pub cluster_name: ::std::option::Option<::std::string::String>,
    /// <p>An object representing an OpenID Connect (OIDC) identity provider configuration.</p>
    pub oidc: ::std::option::Option<crate::types::OidcIdentityProviderConfigRequest>,
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
}
impl AssociateIdentityProviderConfigInput {
    /// <p>The name of your cluster.</p>
    pub fn cluster_name(&self) -> ::std::option::Option<&str> {
        self.cluster_name.as_deref()
    }
    /// <p>An object representing an OpenID Connect (OIDC) identity provider configuration.</p>
    pub fn oidc(&self) -> ::std::option::Option<&crate::types::OidcIdentityProviderConfigRequest> {
        self.oidc.as_ref()
    }
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
}
impl AssociateIdentityProviderConfigInput {
    /// Creates a new builder-style object to manufacture [`AssociateIdentityProviderConfigInput`](crate::operation::associate_identity_provider_config::AssociateIdentityProviderConfigInput).
    pub fn builder() -> crate::operation::associate_identity_provider_config::builders::AssociateIdentityProviderConfigInputBuilder {
        crate::operation::associate_identity_provider_config::builders::AssociateIdentityProviderConfigInputBuilder::default()
    }
}

/// A builder for [`AssociateIdentityProviderConfigInput`](crate::operation::associate_identity_provider_config::AssociateIdentityProviderConfigInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateIdentityProviderConfigInputBuilder {
    pub(crate) cluster_name: ::std::option::Option<::std::string::String>,
    pub(crate) oidc: ::std::option::Option<crate::types::OidcIdentityProviderConfigRequest>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
}
impl AssociateIdentityProviderConfigInputBuilder {
    /// <p>The name of your cluster.</p>
    /// This field is required.
    pub fn cluster_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of your cluster.</p>
    pub fn set_cluster_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_name = input;
        self
    }
    /// <p>The name of your cluster.</p>
    pub fn get_cluster_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_name
    }
    /// <p>An object representing an OpenID Connect (OIDC) identity provider configuration.</p>
    /// This field is required.
    pub fn oidc(mut self, input: crate::types::OidcIdentityProviderConfigRequest) -> Self {
        self.oidc = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object representing an OpenID Connect (OIDC) identity provider configuration.</p>
    pub fn set_oidc(mut self, input: ::std::option::Option<crate::types::OidcIdentityProviderConfigRequest>) -> Self {
        self.oidc = input;
        self
    }
    /// <p>An object representing an OpenID Connect (OIDC) identity provider configuration.</p>
    pub fn get_oidc(&self) -> &::std::option::Option<crate::types::OidcIdentityProviderConfigRequest> {
        &self.oidc
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Metadata that assists with categorization and organization. Each tag consists of a key and an optional value. You define both. Tags don't propagate to any other cluster or Amazon Web Services resources.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>A unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// Consumes the builder and constructs a [`AssociateIdentityProviderConfigInput`](crate::operation::associate_identity_provider_config::AssociateIdentityProviderConfigInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::associate_identity_provider_config::AssociateIdentityProviderConfigInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::associate_identity_provider_config::AssociateIdentityProviderConfigInput {
                cluster_name: self.cluster_name,
                oidc: self.oidc,
                tags: self.tags,
                client_request_token: self.client_request_token,
            },
        )
    }
}
