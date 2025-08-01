// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAppAuthorizationInput {
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub app_bundle_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The name of the application.</p>
    /// <p>Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>SLACK</code></p></li>
    /// <li>
    /// <p><code>ASANA</code></p></li>
    /// <li>
    /// <p><code>JIRA</code></p></li>
    /// <li>
    /// <p><code>M365</code></p></li>
    /// <li>
    /// <p><code>M365AUDITLOGS</code></p></li>
    /// <li>
    /// <p><code>ZOOM</code></p></li>
    /// <li>
    /// <p><code>ZENDESK</code></p></li>
    /// <li>
    /// <p><code>OKTA</code></p></li>
    /// <li>
    /// <p><code>GOOGLE</code></p></li>
    /// <li>
    /// <p><code>DROPBOX</code></p></li>
    /// <li>
    /// <p><code>SMARTSHEET</code></p></li>
    /// <li>
    /// <p><code>CISCO</code></p></li>
    /// </ul>
    pub app: ::std::option::Option<::std::string::String>,
    /// <p>Contains credentials for the application, such as an API key or OAuth2 client ID and secret.</p>
    /// <p>Specify credentials that match the authorization type for your request. For example, if the authorization type for your request is OAuth2 (<code>oauth2</code>), then you should provide only the OAuth2 credentials.</p>
    pub credential: ::std::option::Option<crate::types::Credential>,
    /// <p>Contains information about an application tenant, such as the application display name and identifier.</p>
    pub tenant: ::std::option::Option<crate::types::Tenant>,
    /// <p>The authorization type for the app authorization.</p>
    pub auth_type: ::std::option::Option<crate::types::AuthType>,
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateAppAuthorizationInput {
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub fn app_bundle_identifier(&self) -> ::std::option::Option<&str> {
        self.app_bundle_identifier.as_deref()
    }
    /// <p>The name of the application.</p>
    /// <p>Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>SLACK</code></p></li>
    /// <li>
    /// <p><code>ASANA</code></p></li>
    /// <li>
    /// <p><code>JIRA</code></p></li>
    /// <li>
    /// <p><code>M365</code></p></li>
    /// <li>
    /// <p><code>M365AUDITLOGS</code></p></li>
    /// <li>
    /// <p><code>ZOOM</code></p></li>
    /// <li>
    /// <p><code>ZENDESK</code></p></li>
    /// <li>
    /// <p><code>OKTA</code></p></li>
    /// <li>
    /// <p><code>GOOGLE</code></p></li>
    /// <li>
    /// <p><code>DROPBOX</code></p></li>
    /// <li>
    /// <p><code>SMARTSHEET</code></p></li>
    /// <li>
    /// <p><code>CISCO</code></p></li>
    /// </ul>
    pub fn app(&self) -> ::std::option::Option<&str> {
        self.app.as_deref()
    }
    /// <p>Contains credentials for the application, such as an API key or OAuth2 client ID and secret.</p>
    /// <p>Specify credentials that match the authorization type for your request. For example, if the authorization type for your request is OAuth2 (<code>oauth2</code>), then you should provide only the OAuth2 credentials.</p>
    pub fn credential(&self) -> ::std::option::Option<&crate::types::Credential> {
        self.credential.as_ref()
    }
    /// <p>Contains information about an application tenant, such as the application display name and identifier.</p>
    pub fn tenant(&self) -> ::std::option::Option<&crate::types::Tenant> {
        self.tenant.as_ref()
    }
    /// <p>The authorization type for the app authorization.</p>
    pub fn auth_type(&self) -> ::std::option::Option<&crate::types::AuthType> {
        self.auth_type.as_ref()
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateAppAuthorizationInput {
    /// Creates a new builder-style object to manufacture [`CreateAppAuthorizationInput`](crate::operation::create_app_authorization::CreateAppAuthorizationInput).
    pub fn builder() -> crate::operation::create_app_authorization::builders::CreateAppAuthorizationInputBuilder {
        crate::operation::create_app_authorization::builders::CreateAppAuthorizationInputBuilder::default()
    }
}

/// A builder for [`CreateAppAuthorizationInput`](crate::operation::create_app_authorization::CreateAppAuthorizationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAppAuthorizationInputBuilder {
    pub(crate) app_bundle_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) app: ::std::option::Option<::std::string::String>,
    pub(crate) credential: ::std::option::Option<crate::types::Credential>,
    pub(crate) tenant: ::std::option::Option<crate::types::Tenant>,
    pub(crate) auth_type: ::std::option::Option<crate::types::AuthType>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateAppAuthorizationInputBuilder {
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    /// This field is required.
    pub fn app_bundle_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_bundle_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub fn set_app_bundle_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_bundle_identifier = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) or Universal Unique Identifier (UUID) of the app bundle to use for the request.</p>
    pub fn get_app_bundle_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_bundle_identifier
    }
    /// <p>The name of the application.</p>
    /// <p>Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>SLACK</code></p></li>
    /// <li>
    /// <p><code>ASANA</code></p></li>
    /// <li>
    /// <p><code>JIRA</code></p></li>
    /// <li>
    /// <p><code>M365</code></p></li>
    /// <li>
    /// <p><code>M365AUDITLOGS</code></p></li>
    /// <li>
    /// <p><code>ZOOM</code></p></li>
    /// <li>
    /// <p><code>ZENDESK</code></p></li>
    /// <li>
    /// <p><code>OKTA</code></p></li>
    /// <li>
    /// <p><code>GOOGLE</code></p></li>
    /// <li>
    /// <p><code>DROPBOX</code></p></li>
    /// <li>
    /// <p><code>SMARTSHEET</code></p></li>
    /// <li>
    /// <p><code>CISCO</code></p></li>
    /// </ul>
    /// This field is required.
    pub fn app(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the application.</p>
    /// <p>Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>SLACK</code></p></li>
    /// <li>
    /// <p><code>ASANA</code></p></li>
    /// <li>
    /// <p><code>JIRA</code></p></li>
    /// <li>
    /// <p><code>M365</code></p></li>
    /// <li>
    /// <p><code>M365AUDITLOGS</code></p></li>
    /// <li>
    /// <p><code>ZOOM</code></p></li>
    /// <li>
    /// <p><code>ZENDESK</code></p></li>
    /// <li>
    /// <p><code>OKTA</code></p></li>
    /// <li>
    /// <p><code>GOOGLE</code></p></li>
    /// <li>
    /// <p><code>DROPBOX</code></p></li>
    /// <li>
    /// <p><code>SMARTSHEET</code></p></li>
    /// <li>
    /// <p><code>CISCO</code></p></li>
    /// </ul>
    pub fn set_app(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app = input;
        self
    }
    /// <p>The name of the application.</p>
    /// <p>Valid values are:</p>
    /// <ul>
    /// <li>
    /// <p><code>SLACK</code></p></li>
    /// <li>
    /// <p><code>ASANA</code></p></li>
    /// <li>
    /// <p><code>JIRA</code></p></li>
    /// <li>
    /// <p><code>M365</code></p></li>
    /// <li>
    /// <p><code>M365AUDITLOGS</code></p></li>
    /// <li>
    /// <p><code>ZOOM</code></p></li>
    /// <li>
    /// <p><code>ZENDESK</code></p></li>
    /// <li>
    /// <p><code>OKTA</code></p></li>
    /// <li>
    /// <p><code>GOOGLE</code></p></li>
    /// <li>
    /// <p><code>DROPBOX</code></p></li>
    /// <li>
    /// <p><code>SMARTSHEET</code></p></li>
    /// <li>
    /// <p><code>CISCO</code></p></li>
    /// </ul>
    pub fn get_app(&self) -> &::std::option::Option<::std::string::String> {
        &self.app
    }
    /// <p>Contains credentials for the application, such as an API key or OAuth2 client ID and secret.</p>
    /// <p>Specify credentials that match the authorization type for your request. For example, if the authorization type for your request is OAuth2 (<code>oauth2</code>), then you should provide only the OAuth2 credentials.</p>
    /// This field is required.
    pub fn credential(mut self, input: crate::types::Credential) -> Self {
        self.credential = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains credentials for the application, such as an API key or OAuth2 client ID and secret.</p>
    /// <p>Specify credentials that match the authorization type for your request. For example, if the authorization type for your request is OAuth2 (<code>oauth2</code>), then you should provide only the OAuth2 credentials.</p>
    pub fn set_credential(mut self, input: ::std::option::Option<crate::types::Credential>) -> Self {
        self.credential = input;
        self
    }
    /// <p>Contains credentials for the application, such as an API key or OAuth2 client ID and secret.</p>
    /// <p>Specify credentials that match the authorization type for your request. For example, if the authorization type for your request is OAuth2 (<code>oauth2</code>), then you should provide only the OAuth2 credentials.</p>
    pub fn get_credential(&self) -> &::std::option::Option<crate::types::Credential> {
        &self.credential
    }
    /// <p>Contains information about an application tenant, such as the application display name and identifier.</p>
    /// This field is required.
    pub fn tenant(mut self, input: crate::types::Tenant) -> Self {
        self.tenant = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about an application tenant, such as the application display name and identifier.</p>
    pub fn set_tenant(mut self, input: ::std::option::Option<crate::types::Tenant>) -> Self {
        self.tenant = input;
        self
    }
    /// <p>Contains information about an application tenant, such as the application display name and identifier.</p>
    pub fn get_tenant(&self) -> &::std::option::Option<crate::types::Tenant> {
        &self.tenant
    }
    /// <p>The authorization type for the app authorization.</p>
    /// This field is required.
    pub fn auth_type(mut self, input: crate::types::AuthType) -> Self {
        self.auth_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The authorization type for the app authorization.</p>
    pub fn set_auth_type(mut self, input: ::std::option::Option<crate::types::AuthType>) -> Self {
        self.auth_type = input;
        self
    }
    /// <p>The authorization type for the app authorization.</p>
    pub fn get_auth_type(&self) -> &::std::option::Option<crate::types::AuthType> {
        &self.auth_type
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Specifies a unique, case-sensitive identifier that you provide to ensure the idempotency of the request. This lets you safely retry the request without accidentally performing the same operation a second time. Passing the same value to a later call to an operation requires that you also pass the same value for all other parameters. We recommend that you use a <a href="https://wikipedia.org/wiki/Universally_unique_identifier">UUID type of value</a>.</p>
    /// <p>If you don't provide this value, then Amazon Web Services generates a random one for you.</p>
    /// <p>If you retry the operation with the same <code>ClientToken</code>, but with different parameters, the retry fails with an <code>IdempotentParameterMismatch</code> error.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A map of the key-value pairs of the tag or tags to assign to the resource.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateAppAuthorizationInput`](crate::operation::create_app_authorization::CreateAppAuthorizationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_app_authorization::CreateAppAuthorizationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_app_authorization::CreateAppAuthorizationInput {
            app_bundle_identifier: self.app_bundle_identifier,
            app: self.app,
            credential: self.credential,
            tenant: self.tenant,
            auth_type: self.auth_type,
            client_token: self.client_token,
            tags: self.tags,
        })
    }
}
