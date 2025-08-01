// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies a version of a table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TableVersion {
    /// <p>The table in question.</p>
    pub table: ::std::option::Option<crate::types::Table>,
    /// <p>The ID value that identifies this table version. A <code>VersionId</code> is a string representation of an integer. Each version is incremented by 1.</p>
    pub version_id: ::std::option::Option<::std::string::String>,
}
impl TableVersion {
    /// <p>The table in question.</p>
    pub fn table(&self) -> ::std::option::Option<&crate::types::Table> {
        self.table.as_ref()
    }
    /// <p>The ID value that identifies this table version. A <code>VersionId</code> is a string representation of an integer. Each version is incremented by 1.</p>
    pub fn version_id(&self) -> ::std::option::Option<&str> {
        self.version_id.as_deref()
    }
}
impl TableVersion {
    /// Creates a new builder-style object to manufacture [`TableVersion`](crate::types::TableVersion).
    pub fn builder() -> crate::types::builders::TableVersionBuilder {
        crate::types::builders::TableVersionBuilder::default()
    }
}

/// A builder for [`TableVersion`](crate::types::TableVersion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TableVersionBuilder {
    pub(crate) table: ::std::option::Option<crate::types::Table>,
    pub(crate) version_id: ::std::option::Option<::std::string::String>,
}
impl TableVersionBuilder {
    /// <p>The table in question.</p>
    pub fn table(mut self, input: crate::types::Table) -> Self {
        self.table = ::std::option::Option::Some(input);
        self
    }
    /// <p>The table in question.</p>
    pub fn set_table(mut self, input: ::std::option::Option<crate::types::Table>) -> Self {
        self.table = input;
        self
    }
    /// <p>The table in question.</p>
    pub fn get_table(&self) -> &::std::option::Option<crate::types::Table> {
        &self.table
    }
    /// <p>The ID value that identifies this table version. A <code>VersionId</code> is a string representation of an integer. Each version is incremented by 1.</p>
    pub fn version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID value that identifies this table version. A <code>VersionId</code> is a string representation of an integer. Each version is incremented by 1.</p>
    pub fn set_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_id = input;
        self
    }
    /// <p>The ID value that identifies this table version. A <code>VersionId</code> is a string representation of an integer. Each version is incremented by 1.</p>
    pub fn get_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_id
    }
    /// Consumes the builder and constructs a [`TableVersion`](crate::types::TableVersion).
    pub fn build(self) -> crate::types::TableVersion {
        crate::types::TableVersion {
            table: self.table,
            version_id: self.version_id,
        }
    }
}
