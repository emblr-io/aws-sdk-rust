// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDataCatalogInput {
    /// <p>The name of the data catalog to delete.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Deletes the Athena Data Catalog. You can only use this with the <code>FEDERATED</code> catalogs. You usually perform this before registering the connector with Glue Data Catalog. After deletion, you will have to manage the Glue Connection and Lambda function.</p>
    pub delete_catalog_only: ::std::option::Option<bool>,
}
impl DeleteDataCatalogInput {
    /// <p>The name of the data catalog to delete.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Deletes the Athena Data Catalog. You can only use this with the <code>FEDERATED</code> catalogs. You usually perform this before registering the connector with Glue Data Catalog. After deletion, you will have to manage the Glue Connection and Lambda function.</p>
    pub fn delete_catalog_only(&self) -> ::std::option::Option<bool> {
        self.delete_catalog_only
    }
}
impl DeleteDataCatalogInput {
    /// Creates a new builder-style object to manufacture [`DeleteDataCatalogInput`](crate::operation::delete_data_catalog::DeleteDataCatalogInput).
    pub fn builder() -> crate::operation::delete_data_catalog::builders::DeleteDataCatalogInputBuilder {
        crate::operation::delete_data_catalog::builders::DeleteDataCatalogInputBuilder::default()
    }
}

/// A builder for [`DeleteDataCatalogInput`](crate::operation::delete_data_catalog::DeleteDataCatalogInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDataCatalogInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) delete_catalog_only: ::std::option::Option<bool>,
}
impl DeleteDataCatalogInputBuilder {
    /// <p>The name of the data catalog to delete.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the data catalog to delete.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the data catalog to delete.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Deletes the Athena Data Catalog. You can only use this with the <code>FEDERATED</code> catalogs. You usually perform this before registering the connector with Glue Data Catalog. After deletion, you will have to manage the Glue Connection and Lambda function.</p>
    pub fn delete_catalog_only(mut self, input: bool) -> Self {
        self.delete_catalog_only = ::std::option::Option::Some(input);
        self
    }
    /// <p>Deletes the Athena Data Catalog. You can only use this with the <code>FEDERATED</code> catalogs. You usually perform this before registering the connector with Glue Data Catalog. After deletion, you will have to manage the Glue Connection and Lambda function.</p>
    pub fn set_delete_catalog_only(mut self, input: ::std::option::Option<bool>) -> Self {
        self.delete_catalog_only = input;
        self
    }
    /// <p>Deletes the Athena Data Catalog. You can only use this with the <code>FEDERATED</code> catalogs. You usually perform this before registering the connector with Glue Data Catalog. After deletion, you will have to manage the Glue Connection and Lambda function.</p>
    pub fn get_delete_catalog_only(&self) -> &::std::option::Option<bool> {
        &self.delete_catalog_only
    }
    /// Consumes the builder and constructs a [`DeleteDataCatalogInput`](crate::operation::delete_data_catalog::DeleteDataCatalogInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_data_catalog::DeleteDataCatalogInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_data_catalog::DeleteDataCatalogInput {
            name: self.name,
            delete_catalog_only: self.delete_catalog_only,
        })
    }
}
