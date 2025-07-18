// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the configuration that Amazon AppFlow uses when it catalogs your data. When Amazon AppFlow catalogs your data, it stores metadata in a data catalog.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetadataCatalogConfig {
    /// <p>Specifies the configuration that Amazon AppFlow uses when it catalogs your data with the Glue Data Catalog.</p>
    pub glue_data_catalog: ::std::option::Option<crate::types::GlueDataCatalogConfig>,
}
impl MetadataCatalogConfig {
    /// <p>Specifies the configuration that Amazon AppFlow uses when it catalogs your data with the Glue Data Catalog.</p>
    pub fn glue_data_catalog(&self) -> ::std::option::Option<&crate::types::GlueDataCatalogConfig> {
        self.glue_data_catalog.as_ref()
    }
}
impl MetadataCatalogConfig {
    /// Creates a new builder-style object to manufacture [`MetadataCatalogConfig`](crate::types::MetadataCatalogConfig).
    pub fn builder() -> crate::types::builders::MetadataCatalogConfigBuilder {
        crate::types::builders::MetadataCatalogConfigBuilder::default()
    }
}

/// A builder for [`MetadataCatalogConfig`](crate::types::MetadataCatalogConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetadataCatalogConfigBuilder {
    pub(crate) glue_data_catalog: ::std::option::Option<crate::types::GlueDataCatalogConfig>,
}
impl MetadataCatalogConfigBuilder {
    /// <p>Specifies the configuration that Amazon AppFlow uses when it catalogs your data with the Glue Data Catalog.</p>
    pub fn glue_data_catalog(mut self, input: crate::types::GlueDataCatalogConfig) -> Self {
        self.glue_data_catalog = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the configuration that Amazon AppFlow uses when it catalogs your data with the Glue Data Catalog.</p>
    pub fn set_glue_data_catalog(mut self, input: ::std::option::Option<crate::types::GlueDataCatalogConfig>) -> Self {
        self.glue_data_catalog = input;
        self
    }
    /// <p>Specifies the configuration that Amazon AppFlow uses when it catalogs your data with the Glue Data Catalog.</p>
    pub fn get_glue_data_catalog(&self) -> &::std::option::Option<crate::types::GlueDataCatalogConfig> {
        &self.glue_data_catalog
    }
    /// Consumes the builder and constructs a [`MetadataCatalogConfig`](crate::types::MetadataCatalogConfig).
    pub fn build(self) -> crate::types::MetadataCatalogConfig {
        crate::types::MetadataCatalogConfig {
            glue_data_catalog: self.glue_data_catalog,
        }
    }
}
