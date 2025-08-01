// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Filters the connection definitions that are returned by the <code>GetConnections</code> API operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConnectionsFilter {
    /// <p>A criteria string that must match the criteria recorded in the connection definition for that connection definition to be returned.</p>
    pub match_criteria: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The type of connections to return. Currently, SFTP is not supported.</p>
    pub connection_type: ::std::option::Option<crate::types::ConnectionType>,
    /// <p>Denotes if the connection was created with schema version 1 or 2.</p>
    pub connection_schema_version: ::std::option::Option<i32>,
}
impl GetConnectionsFilter {
    /// <p>A criteria string that must match the criteria recorded in the connection definition for that connection definition to be returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.match_criteria.is_none()`.
    pub fn match_criteria(&self) -> &[::std::string::String] {
        self.match_criteria.as_deref().unwrap_or_default()
    }
    /// <p>The type of connections to return. Currently, SFTP is not supported.</p>
    pub fn connection_type(&self) -> ::std::option::Option<&crate::types::ConnectionType> {
        self.connection_type.as_ref()
    }
    /// <p>Denotes if the connection was created with schema version 1 or 2.</p>
    pub fn connection_schema_version(&self) -> ::std::option::Option<i32> {
        self.connection_schema_version
    }
}
impl GetConnectionsFilter {
    /// Creates a new builder-style object to manufacture [`GetConnectionsFilter`](crate::types::GetConnectionsFilter).
    pub fn builder() -> crate::types::builders::GetConnectionsFilterBuilder {
        crate::types::builders::GetConnectionsFilterBuilder::default()
    }
}

/// A builder for [`GetConnectionsFilter`](crate::types::GetConnectionsFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConnectionsFilterBuilder {
    pub(crate) match_criteria: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) connection_type: ::std::option::Option<crate::types::ConnectionType>,
    pub(crate) connection_schema_version: ::std::option::Option<i32>,
}
impl GetConnectionsFilterBuilder {
    /// Appends an item to `match_criteria`.
    ///
    /// To override the contents of this collection use [`set_match_criteria`](Self::set_match_criteria).
    ///
    /// <p>A criteria string that must match the criteria recorded in the connection definition for that connection definition to be returned.</p>
    pub fn match_criteria(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.match_criteria.unwrap_or_default();
        v.push(input.into());
        self.match_criteria = ::std::option::Option::Some(v);
        self
    }
    /// <p>A criteria string that must match the criteria recorded in the connection definition for that connection definition to be returned.</p>
    pub fn set_match_criteria(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.match_criteria = input;
        self
    }
    /// <p>A criteria string that must match the criteria recorded in the connection definition for that connection definition to be returned.</p>
    pub fn get_match_criteria(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.match_criteria
    }
    /// <p>The type of connections to return. Currently, SFTP is not supported.</p>
    pub fn connection_type(mut self, input: crate::types::ConnectionType) -> Self {
        self.connection_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of connections to return. Currently, SFTP is not supported.</p>
    pub fn set_connection_type(mut self, input: ::std::option::Option<crate::types::ConnectionType>) -> Self {
        self.connection_type = input;
        self
    }
    /// <p>The type of connections to return. Currently, SFTP is not supported.</p>
    pub fn get_connection_type(&self) -> &::std::option::Option<crate::types::ConnectionType> {
        &self.connection_type
    }
    /// <p>Denotes if the connection was created with schema version 1 or 2.</p>
    pub fn connection_schema_version(mut self, input: i32) -> Self {
        self.connection_schema_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>Denotes if the connection was created with schema version 1 or 2.</p>
    pub fn set_connection_schema_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.connection_schema_version = input;
        self
    }
    /// <p>Denotes if the connection was created with schema version 1 or 2.</p>
    pub fn get_connection_schema_version(&self) -> &::std::option::Option<i32> {
        &self.connection_schema_version
    }
    /// Consumes the builder and constructs a [`GetConnectionsFilter`](crate::types::GetConnectionsFilter).
    pub fn build(self) -> crate::types::GetConnectionsFilter {
        crate::types::GetConnectionsFilter {
            match_criteria: self.match_criteria,
            connection_type: self.connection_type,
            connection_schema_version: self.connection_schema_version,
        }
    }
}
