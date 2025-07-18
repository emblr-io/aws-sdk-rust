// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of a resource server configuration and associated custom scopes in a user pool.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceServerType {
    /// <p>The ID of the user pool that contains the resource server configuration.</p>
    pub user_pool_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique resource server identifier for the resource server. The identifier can be an API friendly name like <code>solar-system-data</code>. You can also set an API URL like <code>https://solar-system-data-api.example.com</code> as your identifier.</p>
    /// <p>Amazon Cognito represents scopes in the access token in the format <code>$resource-server-identifier/$scope</code>. Longer scope-identifier strings increase the size of your access tokens.</p>
    pub identifier: ::std::option::Option<::std::string::String>,
    /// <p>The name of the resource server.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A list of scopes that are defined for the resource server.</p>
    pub scopes: ::std::option::Option<::std::vec::Vec<crate::types::ResourceServerScopeType>>,
}
impl ResourceServerType {
    /// <p>The ID of the user pool that contains the resource server configuration.</p>
    pub fn user_pool_id(&self) -> ::std::option::Option<&str> {
        self.user_pool_id.as_deref()
    }
    /// <p>A unique resource server identifier for the resource server. The identifier can be an API friendly name like <code>solar-system-data</code>. You can also set an API URL like <code>https://solar-system-data-api.example.com</code> as your identifier.</p>
    /// <p>Amazon Cognito represents scopes in the access token in the format <code>$resource-server-identifier/$scope</code>. Longer scope-identifier strings increase the size of your access tokens.</p>
    pub fn identifier(&self) -> ::std::option::Option<&str> {
        self.identifier.as_deref()
    }
    /// <p>The name of the resource server.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A list of scopes that are defined for the resource server.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.scopes.is_none()`.
    pub fn scopes(&self) -> &[crate::types::ResourceServerScopeType] {
        self.scopes.as_deref().unwrap_or_default()
    }
}
impl ResourceServerType {
    /// Creates a new builder-style object to manufacture [`ResourceServerType`](crate::types::ResourceServerType).
    pub fn builder() -> crate::types::builders::ResourceServerTypeBuilder {
        crate::types::builders::ResourceServerTypeBuilder::default()
    }
}

/// A builder for [`ResourceServerType`](crate::types::ResourceServerType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceServerTypeBuilder {
    pub(crate) user_pool_id: ::std::option::Option<::std::string::String>,
    pub(crate) identifier: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) scopes: ::std::option::Option<::std::vec::Vec<crate::types::ResourceServerScopeType>>,
}
impl ResourceServerTypeBuilder {
    /// <p>The ID of the user pool that contains the resource server configuration.</p>
    pub fn user_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the user pool that contains the resource server configuration.</p>
    pub fn set_user_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_id = input;
        self
    }
    /// <p>The ID of the user pool that contains the resource server configuration.</p>
    pub fn get_user_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_id
    }
    /// <p>A unique resource server identifier for the resource server. The identifier can be an API friendly name like <code>solar-system-data</code>. You can also set an API URL like <code>https://solar-system-data-api.example.com</code> as your identifier.</p>
    /// <p>Amazon Cognito represents scopes in the access token in the format <code>$resource-server-identifier/$scope</code>. Longer scope-identifier strings increase the size of your access tokens.</p>
    pub fn identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique resource server identifier for the resource server. The identifier can be an API friendly name like <code>solar-system-data</code>. You can also set an API URL like <code>https://solar-system-data-api.example.com</code> as your identifier.</p>
    /// <p>Amazon Cognito represents scopes in the access token in the format <code>$resource-server-identifier/$scope</code>. Longer scope-identifier strings increase the size of your access tokens.</p>
    pub fn set_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identifier = input;
        self
    }
    /// <p>A unique resource server identifier for the resource server. The identifier can be an API friendly name like <code>solar-system-data</code>. You can also set an API URL like <code>https://solar-system-data-api.example.com</code> as your identifier.</p>
    /// <p>Amazon Cognito represents scopes in the access token in the format <code>$resource-server-identifier/$scope</code>. Longer scope-identifier strings increase the size of your access tokens.</p>
    pub fn get_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.identifier
    }
    /// <p>The name of the resource server.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the resource server.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the resource server.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `scopes`.
    ///
    /// To override the contents of this collection use [`set_scopes`](Self::set_scopes).
    ///
    /// <p>A list of scopes that are defined for the resource server.</p>
    pub fn scopes(mut self, input: crate::types::ResourceServerScopeType) -> Self {
        let mut v = self.scopes.unwrap_or_default();
        v.push(input);
        self.scopes = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of scopes that are defined for the resource server.</p>
    pub fn set_scopes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ResourceServerScopeType>>) -> Self {
        self.scopes = input;
        self
    }
    /// <p>A list of scopes that are defined for the resource server.</p>
    pub fn get_scopes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ResourceServerScopeType>> {
        &self.scopes
    }
    /// Consumes the builder and constructs a [`ResourceServerType`](crate::types::ResourceServerType).
    pub fn build(self) -> crate::types::ResourceServerType {
        crate::types::ResourceServerType {
            user_pool_id: self.user_pool_id,
            identifier: self.identifier,
            name: self.name,
            scopes: self.scopes,
        }
    }
}
