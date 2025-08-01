// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListConnectorEntitiesOutput {
    /// <p>The response of <code>ListConnectorEntities</code> lists entities grouped by category. This map's key represents the group name, and its value contains the list of entities belonging to that group.</p>
    pub connector_entity_map: ::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ConnectorEntity>>,
    /// <p>A token that you specify in your next <code>ListConnectorEntities</code> operation to get the next page of results in paginated response. The <code>ListConnectorEntities</code> operation provides this token if the response is too big for the page size.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListConnectorEntitiesOutput {
    /// <p>The response of <code>ListConnectorEntities</code> lists entities grouped by category. This map's key represents the group name, and its value contains the list of entities belonging to that group.</p>
    pub fn connector_entity_map(&self) -> &::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ConnectorEntity>> {
        &self.connector_entity_map
    }
    /// <p>A token that you specify in your next <code>ListConnectorEntities</code> operation to get the next page of results in paginated response. The <code>ListConnectorEntities</code> operation provides this token if the response is too big for the page size.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListConnectorEntitiesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListConnectorEntitiesOutput {
    /// Creates a new builder-style object to manufacture [`ListConnectorEntitiesOutput`](crate::operation::list_connector_entities::ListConnectorEntitiesOutput).
    pub fn builder() -> crate::operation::list_connector_entities::builders::ListConnectorEntitiesOutputBuilder {
        crate::operation::list_connector_entities::builders::ListConnectorEntitiesOutputBuilder::default()
    }
}

/// A builder for [`ListConnectorEntitiesOutput`](crate::operation::list_connector_entities::ListConnectorEntitiesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListConnectorEntitiesOutputBuilder {
    pub(crate) connector_entity_map:
        ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ConnectorEntity>>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListConnectorEntitiesOutputBuilder {
    /// Adds a key-value pair to `connector_entity_map`.
    ///
    /// To override the contents of this collection use [`set_connector_entity_map`](Self::set_connector_entity_map).
    ///
    /// <p>The response of <code>ListConnectorEntities</code> lists entities grouped by category. This map's key represents the group name, and its value contains the list of entities belonging to that group.</p>
    pub fn connector_entity_map(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: ::std::vec::Vec<crate::types::ConnectorEntity>,
    ) -> Self {
        let mut hash_map = self.connector_entity_map.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.connector_entity_map = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The response of <code>ListConnectorEntities</code> lists entities grouped by category. This map's key represents the group name, and its value contains the list of entities belonging to that group.</p>
    pub fn set_connector_entity_map(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ConnectorEntity>>>,
    ) -> Self {
        self.connector_entity_map = input;
        self
    }
    /// <p>The response of <code>ListConnectorEntities</code> lists entities grouped by category. This map's key represents the group name, and its value contains the list of entities belonging to that group.</p>
    pub fn get_connector_entity_map(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<crate::types::ConnectorEntity>>> {
        &self.connector_entity_map
    }
    /// <p>A token that you specify in your next <code>ListConnectorEntities</code> operation to get the next page of results in paginated response. The <code>ListConnectorEntities</code> operation provides this token if the response is too big for the page size.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token that you specify in your next <code>ListConnectorEntities</code> operation to get the next page of results in paginated response. The <code>ListConnectorEntities</code> operation provides this token if the response is too big for the page size.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token that you specify in your next <code>ListConnectorEntities</code> operation to get the next page of results in paginated response. The <code>ListConnectorEntities</code> operation provides this token if the response is too big for the page size.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ListConnectorEntitiesOutput`](crate::operation::list_connector_entities::ListConnectorEntitiesOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`connector_entity_map`](crate::operation::list_connector_entities::builders::ListConnectorEntitiesOutputBuilder::connector_entity_map)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_connector_entities::ListConnectorEntitiesOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_connector_entities::ListConnectorEntitiesOutput {
            connector_entity_map: self.connector_entity_map.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "connector_entity_map",
                    "connector_entity_map was not specified but it is required when building ListConnectorEntitiesOutput",
                )
            })?,
            next_token: self.next_token,
            _request_id: self._request_id,
        })
    }
}
