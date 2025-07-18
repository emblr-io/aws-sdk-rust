// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines information about the Glue data source that contains the training data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataSource {
    /// <p>A GlueDataSource object that defines the catalog ID, database name, and table name for the training data.</p>
    pub glue_data_source: ::std::option::Option<crate::types::GlueDataSource>,
}
impl DataSource {
    /// <p>A GlueDataSource object that defines the catalog ID, database name, and table name for the training data.</p>
    pub fn glue_data_source(&self) -> ::std::option::Option<&crate::types::GlueDataSource> {
        self.glue_data_source.as_ref()
    }
}
impl DataSource {
    /// Creates a new builder-style object to manufacture [`DataSource`](crate::types::DataSource).
    pub fn builder() -> crate::types::builders::DataSourceBuilder {
        crate::types::builders::DataSourceBuilder::default()
    }
}

/// A builder for [`DataSource`](crate::types::DataSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataSourceBuilder {
    pub(crate) glue_data_source: ::std::option::Option<crate::types::GlueDataSource>,
}
impl DataSourceBuilder {
    /// <p>A GlueDataSource object that defines the catalog ID, database name, and table name for the training data.</p>
    /// This field is required.
    pub fn glue_data_source(mut self, input: crate::types::GlueDataSource) -> Self {
        self.glue_data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>A GlueDataSource object that defines the catalog ID, database name, and table name for the training data.</p>
    pub fn set_glue_data_source(mut self, input: ::std::option::Option<crate::types::GlueDataSource>) -> Self {
        self.glue_data_source = input;
        self
    }
    /// <p>A GlueDataSource object that defines the catalog ID, database name, and table name for the training data.</p>
    pub fn get_glue_data_source(&self) -> &::std::option::Option<crate::types::GlueDataSource> {
        &self.glue_data_source
    }
    /// Consumes the builder and constructs a [`DataSource`](crate::types::DataSource).
    pub fn build(self) -> crate::types::DataSource {
        crate::types::DataSource {
            glue_data_source: self.glue_data_source,
        }
    }
}
