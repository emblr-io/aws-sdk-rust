// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The connector metadata specific to Amazon Redshift.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RedshiftMetadata {}
impl RedshiftMetadata {
    /// Creates a new builder-style object to manufacture [`RedshiftMetadata`](crate::types::RedshiftMetadata).
    pub fn builder() -> crate::types::builders::RedshiftMetadataBuilder {
        crate::types::builders::RedshiftMetadataBuilder::default()
    }
}

/// A builder for [`RedshiftMetadata`](crate::types::RedshiftMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RedshiftMetadataBuilder {}
impl RedshiftMetadataBuilder {
    /// Consumes the builder and constructs a [`RedshiftMetadata`](crate::types::RedshiftMetadata).
    pub fn build(self) -> crate::types::RedshiftMetadata {
        crate::types::RedshiftMetadata {}
    }
}
