// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateTableObjectsInput {
    /// <p>The catalog containing the governed table to update. Defaults to the caller’s account ID.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
    /// <p>The database containing the governed table to update.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>The governed table to update.</p>
    pub table_name: ::std::option::Option<::std::string::String>,
    /// <p>The transaction at which to do the write.</p>
    pub transaction_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>WriteOperation</code> objects that define an object to add to or delete from the manifest for a governed table.</p>
    pub write_operations: ::std::option::Option<::std::vec::Vec<crate::types::WriteOperation>>,
}
impl UpdateTableObjectsInput {
    /// <p>The catalog containing the governed table to update. Defaults to the caller’s account ID.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
    /// <p>The database containing the governed table to update.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>The governed table to update.</p>
    pub fn table_name(&self) -> ::std::option::Option<&str> {
        self.table_name.as_deref()
    }
    /// <p>The transaction at which to do the write.</p>
    pub fn transaction_id(&self) -> ::std::option::Option<&str> {
        self.transaction_id.as_deref()
    }
    /// <p>A list of <code>WriteOperation</code> objects that define an object to add to or delete from the manifest for a governed table.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.write_operations.is_none()`.
    pub fn write_operations(&self) -> &[crate::types::WriteOperation] {
        self.write_operations.as_deref().unwrap_or_default()
    }
}
impl UpdateTableObjectsInput {
    /// Creates a new builder-style object to manufacture [`UpdateTableObjectsInput`](crate::operation::update_table_objects::UpdateTableObjectsInput).
    pub fn builder() -> crate::operation::update_table_objects::builders::UpdateTableObjectsInputBuilder {
        crate::operation::update_table_objects::builders::UpdateTableObjectsInputBuilder::default()
    }
}

/// A builder for [`UpdateTableObjectsInput`](crate::operation::update_table_objects::UpdateTableObjectsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateTableObjectsInputBuilder {
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) transaction_id: ::std::option::Option<::std::string::String>,
    pub(crate) write_operations: ::std::option::Option<::std::vec::Vec<crate::types::WriteOperation>>,
}
impl UpdateTableObjectsInputBuilder {
    /// <p>The catalog containing the governed table to update. Defaults to the caller’s account ID.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The catalog containing the governed table to update. Defaults to the caller’s account ID.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The catalog containing the governed table to update. Defaults to the caller’s account ID.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// <p>The database containing the governed table to update.</p>
    /// This field is required.
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The database containing the governed table to update.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>The database containing the governed table to update.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>The governed table to update.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The governed table to update.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The governed table to update.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>The transaction at which to do the write.</p>
    pub fn transaction_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transaction_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transaction at which to do the write.</p>
    pub fn set_transaction_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transaction_id = input;
        self
    }
    /// <p>The transaction at which to do the write.</p>
    pub fn get_transaction_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.transaction_id
    }
    /// Appends an item to `write_operations`.
    ///
    /// To override the contents of this collection use [`set_write_operations`](Self::set_write_operations).
    ///
    /// <p>A list of <code>WriteOperation</code> objects that define an object to add to or delete from the manifest for a governed table.</p>
    pub fn write_operations(mut self, input: crate::types::WriteOperation) -> Self {
        let mut v = self.write_operations.unwrap_or_default();
        v.push(input);
        self.write_operations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>WriteOperation</code> objects that define an object to add to or delete from the manifest for a governed table.</p>
    pub fn set_write_operations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::WriteOperation>>) -> Self {
        self.write_operations = input;
        self
    }
    /// <p>A list of <code>WriteOperation</code> objects that define an object to add to or delete from the manifest for a governed table.</p>
    pub fn get_write_operations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::WriteOperation>> {
        &self.write_operations
    }
    /// Consumes the builder and constructs a [`UpdateTableObjectsInput`](crate::operation::update_table_objects::UpdateTableObjectsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_table_objects::UpdateTableObjectsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_table_objects::UpdateTableObjectsInput {
            catalog_id: self.catalog_id,
            database_name: self.database_name,
            table_name: self.table_name,
            transaction_id: self.transaction_id,
            write_operations: self.write_operations,
        })
    }
}
