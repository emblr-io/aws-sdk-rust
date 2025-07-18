// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEntitiesInput {
    /// <p>A name for the connection that has required credentials to query any connection type.</p>
    pub connection_name: ::std::option::Option<::std::string::String>,
    /// <p>The catalog ID of the catalog that contains the connection. This can be null, By default, the Amazon Web Services Account ID is the catalog ID.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>Name of the parent entity for which you want to list the children. This parameter takes a fully-qualified path of the entity in order to list the child entities.</p>
    pub parent_entity_name: ::std::option::Option<::std::string::String>,
    /// <p>A continuation token, included if this is a continuation call.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The API version of the SaaS connector.</p>
    pub data_store_api_version: ::std::option::Option<::std::string::String>,
}
impl ListEntitiesInput {
    /// <p>A name for the connection that has required credentials to query any connection type.</p>
    pub fn connection_name(&self) -> ::std::option::Option<&str> {
        self.connection_name.as_deref()
    }
    /// <p>The catalog ID of the catalog that contains the connection. This can be null, By default, the Amazon Web Services Account ID is the catalog ID.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>Name of the parent entity for which you want to list the children. This parameter takes a fully-qualified path of the entity in order to list the child entities.</p>
    pub fn parent_entity_name(&self) -> ::std::option::Option<&str> {
        self.parent_entity_name.as_deref()
    }
    /// <p>A continuation token, included if this is a continuation call.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The API version of the SaaS connector.</p>
    pub fn data_store_api_version(&self) -> ::std::option::Option<&str> {
        self.data_store_api_version.as_deref()
    }
}
impl ListEntitiesInput {
    /// Creates a new builder-style object to manufacture [`ListEntitiesInput`](crate::operation::list_entities::ListEntitiesInput).
    pub fn builder() -> crate::operation::list_entities::builders::ListEntitiesInputBuilder {
        crate::operation::list_entities::builders::ListEntitiesInputBuilder::default()
    }
}

/// A builder for [`ListEntitiesInput`](crate::operation::list_entities::ListEntitiesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEntitiesInputBuilder {
    pub(crate) connection_name: ::std::option::Option<::std::string::String>,
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) parent_entity_name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) data_store_api_version: ::std::option::Option<::std::string::String>,
}
impl ListEntitiesInputBuilder {
    /// <p>A name for the connection that has required credentials to query any connection type.</p>
    pub fn connection_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connection_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the connection that has required credentials to query any connection type.</p>
    pub fn set_connection_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connection_name = input;
        self
    }
    /// <p>A name for the connection that has required credentials to query any connection type.</p>
    pub fn get_connection_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.connection_name
    }
    /// <p>The catalog ID of the catalog that contains the connection. This can be null, By default, the Amazon Web Services Account ID is the catalog ID.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The catalog ID of the catalog that contains the connection. This can be null, By default, the Amazon Web Services Account ID is the catalog ID.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The catalog ID of the catalog that contains the connection. This can be null, By default, the Amazon Web Services Account ID is the catalog ID.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>Name of the parent entity for which you want to list the children. This parameter takes a fully-qualified path of the entity in order to list the child entities.</p>
    pub fn parent_entity_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.parent_entity_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the parent entity for which you want to list the children. This parameter takes a fully-qualified path of the entity in order to list the child entities.</p>
    pub fn set_parent_entity_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.parent_entity_name = input;
        self
    }
    /// <p>Name of the parent entity for which you want to list the children. This parameter takes a fully-qualified path of the entity in order to list the child entities.</p>
    pub fn get_parent_entity_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.parent_entity_name
    }
    /// <p>A continuation token, included if this is a continuation call.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A continuation token, included if this is a continuation call.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A continuation token, included if this is a continuation call.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The API version of the SaaS connector.</p>
    pub fn data_store_api_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_store_api_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The API version of the SaaS connector.</p>
    pub fn set_data_store_api_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_store_api_version = input;
        self
    }
    /// <p>The API version of the SaaS connector.</p>
    pub fn get_data_store_api_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_store_api_version
    }
    /// Consumes the builder and constructs a [`ListEntitiesInput`](crate::operation::list_entities::ListEntitiesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_entities::ListEntitiesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_entities::ListEntitiesInput {
            connection_name: self.connection_name,
            catalog_id: self.catalog_id,
            parent_entity_name: self.parent_entity_name,
            next_token: self.next_token,
            data_store_api_version: self.data_store_api_version,
        })
    }
}
