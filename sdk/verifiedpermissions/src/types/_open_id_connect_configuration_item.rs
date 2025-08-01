// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains configuration details of an OpenID Connect (OIDC) identity provider, or identity source, that Verified Permissions can use to generate entities from authenticated identities. It specifies the issuer URL, token type that you want to use, and policy store entity details.</p>
/// <p>This data type is part of a <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ConfigurationDetail.html">ConfigurationItem</a> structure, which is a parameter to <a href="https://docs.aws.amazon.com/verifiedpermissions/latest/apireference/API_ListIdentitySources.html">ListIdentitySources</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct OpenIdConnectConfigurationItem {
    /// <p>The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path <code>.well-known/openid-configuration</code>.</p>
    pub issuer: ::std::string::String,
    /// <p>A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.</p>
    pub entity_id_prefix: ::std::option::Option<::std::string::String>,
    /// <p>The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you want to map it to. For example, this object can map the contents of a <code>groups</code> claim to <code>MyCorp::UserGroup</code>.</p>
    pub group_configuration: ::std::option::Option<crate::types::OpenIdConnectGroupConfigurationItem>,
    /// <p>The token type that you want to process from your OIDC identity provider. Your policy store can process either identity (ID) or access tokens from a given OIDC identity source.</p>
    pub token_selection: ::std::option::Option<crate::types::OpenIdConnectTokenSelectionItem>,
}
impl OpenIdConnectConfigurationItem {
    /// <p>The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path <code>.well-known/openid-configuration</code>.</p>
    pub fn issuer(&self) -> &str {
        use std::ops::Deref;
        self.issuer.deref()
    }
    /// <p>A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.</p>
    pub fn entity_id_prefix(&self) -> ::std::option::Option<&str> {
        self.entity_id_prefix.as_deref()
    }
    /// <p>The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you want to map it to. For example, this object can map the contents of a <code>groups</code> claim to <code>MyCorp::UserGroup</code>.</p>
    pub fn group_configuration(&self) -> ::std::option::Option<&crate::types::OpenIdConnectGroupConfigurationItem> {
        self.group_configuration.as_ref()
    }
    /// <p>The token type that you want to process from your OIDC identity provider. Your policy store can process either identity (ID) or access tokens from a given OIDC identity source.</p>
    pub fn token_selection(&self) -> ::std::option::Option<&crate::types::OpenIdConnectTokenSelectionItem> {
        self.token_selection.as_ref()
    }
}
impl ::std::fmt::Debug for OpenIdConnectConfigurationItem {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OpenIdConnectConfigurationItem");
        formatter.field("issuer", &self.issuer);
        formatter.field("entity_id_prefix", &"*** Sensitive Data Redacted ***");
        formatter.field("group_configuration", &self.group_configuration);
        formatter.field("token_selection", &self.token_selection);
        formatter.finish()
    }
}
impl OpenIdConnectConfigurationItem {
    /// Creates a new builder-style object to manufacture [`OpenIdConnectConfigurationItem`](crate::types::OpenIdConnectConfigurationItem).
    pub fn builder() -> crate::types::builders::OpenIdConnectConfigurationItemBuilder {
        crate::types::builders::OpenIdConnectConfigurationItemBuilder::default()
    }
}

/// A builder for [`OpenIdConnectConfigurationItem`](crate::types::OpenIdConnectConfigurationItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct OpenIdConnectConfigurationItemBuilder {
    pub(crate) issuer: ::std::option::Option<::std::string::String>,
    pub(crate) entity_id_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) group_configuration: ::std::option::Option<crate::types::OpenIdConnectGroupConfigurationItem>,
    pub(crate) token_selection: ::std::option::Option<crate::types::OpenIdConnectTokenSelectionItem>,
}
impl OpenIdConnectConfigurationItemBuilder {
    /// <p>The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path <code>.well-known/openid-configuration</code>.</p>
    /// This field is required.
    pub fn issuer(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.issuer = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path <code>.well-known/openid-configuration</code>.</p>
    pub fn set_issuer(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.issuer = input;
        self
    }
    /// <p>The issuer URL of an OIDC identity provider. This URL must have an OIDC discovery endpoint at the path <code>.well-known/openid-configuration</code>.</p>
    pub fn get_issuer(&self) -> &::std::option::Option<::std::string::String> {
        &self.issuer
    }
    /// <p>A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.</p>
    pub fn entity_id_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entity_id_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.</p>
    pub fn set_entity_id_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entity_id_prefix = input;
        self
    }
    /// <p>A descriptive string that you want to prefix to user entities from your OIDC identity provider. For example, if you set an <code>entityIdPrefix</code> of <code>MyOIDCProvider</code>, you can reference principals in your policies in the format <code>MyCorp::User::MyOIDCProvider|Carlos</code>.</p>
    pub fn get_entity_id_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.entity_id_prefix
    }
    /// <p>The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you want to map it to. For example, this object can map the contents of a <code>groups</code> claim to <code>MyCorp::UserGroup</code>.</p>
    pub fn group_configuration(mut self, input: crate::types::OpenIdConnectGroupConfigurationItem) -> Self {
        self.group_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you want to map it to. For example, this object can map the contents of a <code>groups</code> claim to <code>MyCorp::UserGroup</code>.</p>
    pub fn set_group_configuration(mut self, input: ::std::option::Option<crate::types::OpenIdConnectGroupConfigurationItem>) -> Self {
        self.group_configuration = input;
        self
    }
    /// <p>The claim in OIDC identity provider tokens that indicates a user's group membership, and the entity type that you want to map it to. For example, this object can map the contents of a <code>groups</code> claim to <code>MyCorp::UserGroup</code>.</p>
    pub fn get_group_configuration(&self) -> &::std::option::Option<crate::types::OpenIdConnectGroupConfigurationItem> {
        &self.group_configuration
    }
    /// <p>The token type that you want to process from your OIDC identity provider. Your policy store can process either identity (ID) or access tokens from a given OIDC identity source.</p>
    /// This field is required.
    pub fn token_selection(mut self, input: crate::types::OpenIdConnectTokenSelectionItem) -> Self {
        self.token_selection = ::std::option::Option::Some(input);
        self
    }
    /// <p>The token type that you want to process from your OIDC identity provider. Your policy store can process either identity (ID) or access tokens from a given OIDC identity source.</p>
    pub fn set_token_selection(mut self, input: ::std::option::Option<crate::types::OpenIdConnectTokenSelectionItem>) -> Self {
        self.token_selection = input;
        self
    }
    /// <p>The token type that you want to process from your OIDC identity provider. Your policy store can process either identity (ID) or access tokens from a given OIDC identity source.</p>
    pub fn get_token_selection(&self) -> &::std::option::Option<crate::types::OpenIdConnectTokenSelectionItem> {
        &self.token_selection
    }
    /// Consumes the builder and constructs a [`OpenIdConnectConfigurationItem`](crate::types::OpenIdConnectConfigurationItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`issuer`](crate::types::builders::OpenIdConnectConfigurationItemBuilder::issuer)
    pub fn build(self) -> ::std::result::Result<crate::types::OpenIdConnectConfigurationItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OpenIdConnectConfigurationItem {
            issuer: self.issuer.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "issuer",
                    "issuer was not specified but it is required when building OpenIdConnectConfigurationItem",
                )
            })?,
            entity_id_prefix: self.entity_id_prefix,
            group_configuration: self.group_configuration,
            token_selection: self.token_selection,
        })
    }
}
impl ::std::fmt::Debug for OpenIdConnectConfigurationItemBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OpenIdConnectConfigurationItemBuilder");
        formatter.field("issuer", &self.issuer);
        formatter.field("entity_id_prefix", &"*** Sensitive Data Redacted ***");
        formatter.field("group_configuration", &self.group_configuration);
        formatter.field("token_selection", &self.token_selection);
        formatter.finish()
    }
}
