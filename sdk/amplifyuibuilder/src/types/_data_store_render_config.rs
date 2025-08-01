// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the DataStore configuration for an API for a code generation job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataStoreRenderConfig {}
impl DataStoreRenderConfig {
    /// Creates a new builder-style object to manufacture [`DataStoreRenderConfig`](crate::types::DataStoreRenderConfig).
    pub fn builder() -> crate::types::builders::DataStoreRenderConfigBuilder {
        crate::types::builders::DataStoreRenderConfigBuilder::default()
    }
}

/// A builder for [`DataStoreRenderConfig`](crate::types::DataStoreRenderConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataStoreRenderConfigBuilder {}
impl DataStoreRenderConfigBuilder {
    /// Consumes the builder and constructs a [`DataStoreRenderConfig`](crate::types::DataStoreRenderConfig).
    pub fn build(self) -> crate::types::DataStoreRenderConfig {
        crate::types::DataStoreRenderConfig {}
    }
}
