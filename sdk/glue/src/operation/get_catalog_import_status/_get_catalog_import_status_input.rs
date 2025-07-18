// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCatalogImportStatusInput {
    /// <p>The ID of the catalog to migrate. Currently, this should be the Amazon Web Services account ID.</p>
    pub catalog_id: ::std::option::Option<::std::string::String>,
}
impl GetCatalogImportStatusInput {
    /// <p>The ID of the catalog to migrate. Currently, this should be the Amazon Web Services account ID.</p>
    pub fn catalog_id(&self) -> ::std::option::Option<&str> {
        self.catalog_id.as_deref()
    }
}
impl GetCatalogImportStatusInput {
    /// Creates a new builder-style object to manufacture [`GetCatalogImportStatusInput`](crate::operation::get_catalog_import_status::GetCatalogImportStatusInput).
    pub fn builder() -> crate::operation::get_catalog_import_status::builders::GetCatalogImportStatusInputBuilder {
        crate::operation::get_catalog_import_status::builders::GetCatalogImportStatusInputBuilder::default()
    }
}

/// A builder for [`GetCatalogImportStatusInput`](crate::operation::get_catalog_import_status::GetCatalogImportStatusInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCatalogImportStatusInputBuilder {
    pub(crate) catalog_id: ::std::option::Option<::std::string::String>,
}
impl GetCatalogImportStatusInputBuilder {
    /// <p>The ID of the catalog to migrate. Currently, this should be the Amazon Web Services account ID.</p>
    pub fn catalog_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.catalog_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the catalog to migrate. Currently, this should be the Amazon Web Services account ID.</p>
    pub fn set_catalog_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.catalog_id = input;
        self
    }
    /// <p>The ID of the catalog to migrate. Currently, this should be the Amazon Web Services account ID.</p>
    pub fn get_catalog_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.catalog_id
    }
    /// Consumes the builder and constructs a [`GetCatalogImportStatusInput`](crate::operation::get_catalog_import_status::GetCatalogImportStatusInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_catalog_import_status::GetCatalogImportStatusInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_catalog_import_status::GetCatalogImportStatusInput { catalog_id: self.catalog_id })
    }
}
