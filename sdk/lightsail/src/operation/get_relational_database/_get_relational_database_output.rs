// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRelationalDatabaseOutput {
    /// <p>An object describing the specified database.</p>
    pub relational_database: ::std::option::Option<crate::types::RelationalDatabase>,
    _request_id: Option<String>,
}
impl GetRelationalDatabaseOutput {
    /// <p>An object describing the specified database.</p>
    pub fn relational_database(&self) -> ::std::option::Option<&crate::types::RelationalDatabase> {
        self.relational_database.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRelationalDatabaseOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRelationalDatabaseOutput {
    /// Creates a new builder-style object to manufacture [`GetRelationalDatabaseOutput`](crate::operation::get_relational_database::GetRelationalDatabaseOutput).
    pub fn builder() -> crate::operation::get_relational_database::builders::GetRelationalDatabaseOutputBuilder {
        crate::operation::get_relational_database::builders::GetRelationalDatabaseOutputBuilder::default()
    }
}

/// A builder for [`GetRelationalDatabaseOutput`](crate::operation::get_relational_database::GetRelationalDatabaseOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRelationalDatabaseOutputBuilder {
    pub(crate) relational_database: ::std::option::Option<crate::types::RelationalDatabase>,
    _request_id: Option<String>,
}
impl GetRelationalDatabaseOutputBuilder {
    /// <p>An object describing the specified database.</p>
    pub fn relational_database(mut self, input: crate::types::RelationalDatabase) -> Self {
        self.relational_database = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object describing the specified database.</p>
    pub fn set_relational_database(mut self, input: ::std::option::Option<crate::types::RelationalDatabase>) -> Self {
        self.relational_database = input;
        self
    }
    /// <p>An object describing the specified database.</p>
    pub fn get_relational_database(&self) -> &::std::option::Option<crate::types::RelationalDatabase> {
        &self.relational_database
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRelationalDatabaseOutput`](crate::operation::get_relational_database::GetRelationalDatabaseOutput).
    pub fn build(self) -> crate::operation::get_relational_database::GetRelationalDatabaseOutput {
        crate::operation::get_relational_database::GetRelationalDatabaseOutput {
            relational_database: self.relational_database,
            _request_id: self._request_id,
        }
    }
}
