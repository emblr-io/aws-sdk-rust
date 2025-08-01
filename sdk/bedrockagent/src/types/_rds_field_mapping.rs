// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the names of the fields to which to map information about the vector store.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RdsFieldMapping {
    /// <p>The name of the field in which Amazon Bedrock stores the ID for each entry.</p>
    pub primary_key_field: ::std::string::String,
    /// <p>The name of the field in which Amazon Bedrock stores the vector embeddings for your data sources.</p>
    pub vector_field: ::std::string::String,
    /// <p>The name of the field in which Amazon Bedrock stores the raw text from your data. The text is split according to the chunking strategy you choose.</p>
    pub text_field: ::std::string::String,
    /// <p>The name of the field in which Amazon Bedrock stores metadata about the vector store.</p>
    pub metadata_field: ::std::string::String,
    /// <p>Provide a name for the universal metadata field where Amazon Bedrock will store any custom metadata from your data source.</p>
    pub custom_metadata_field: ::std::option::Option<::std::string::String>,
}
impl RdsFieldMapping {
    /// <p>The name of the field in which Amazon Bedrock stores the ID for each entry.</p>
    pub fn primary_key_field(&self) -> &str {
        use std::ops::Deref;
        self.primary_key_field.deref()
    }
    /// <p>The name of the field in which Amazon Bedrock stores the vector embeddings for your data sources.</p>
    pub fn vector_field(&self) -> &str {
        use std::ops::Deref;
        self.vector_field.deref()
    }
    /// <p>The name of the field in which Amazon Bedrock stores the raw text from your data. The text is split according to the chunking strategy you choose.</p>
    pub fn text_field(&self) -> &str {
        use std::ops::Deref;
        self.text_field.deref()
    }
    /// <p>The name of the field in which Amazon Bedrock stores metadata about the vector store.</p>
    pub fn metadata_field(&self) -> &str {
        use std::ops::Deref;
        self.metadata_field.deref()
    }
    /// <p>Provide a name for the universal metadata field where Amazon Bedrock will store any custom metadata from your data source.</p>
    pub fn custom_metadata_field(&self) -> ::std::option::Option<&str> {
        self.custom_metadata_field.as_deref()
    }
}
impl RdsFieldMapping {
    /// Creates a new builder-style object to manufacture [`RdsFieldMapping`](crate::types::RdsFieldMapping).
    pub fn builder() -> crate::types::builders::RdsFieldMappingBuilder {
        crate::types::builders::RdsFieldMappingBuilder::default()
    }
}

/// A builder for [`RdsFieldMapping`](crate::types::RdsFieldMapping).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RdsFieldMappingBuilder {
    pub(crate) primary_key_field: ::std::option::Option<::std::string::String>,
    pub(crate) vector_field: ::std::option::Option<::std::string::String>,
    pub(crate) text_field: ::std::option::Option<::std::string::String>,
    pub(crate) metadata_field: ::std::option::Option<::std::string::String>,
    pub(crate) custom_metadata_field: ::std::option::Option<::std::string::String>,
}
impl RdsFieldMappingBuilder {
    /// <p>The name of the field in which Amazon Bedrock stores the ID for each entry.</p>
    /// This field is required.
    pub fn primary_key_field(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.primary_key_field = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the field in which Amazon Bedrock stores the ID for each entry.</p>
    pub fn set_primary_key_field(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.primary_key_field = input;
        self
    }
    /// <p>The name of the field in which Amazon Bedrock stores the ID for each entry.</p>
    pub fn get_primary_key_field(&self) -> &::std::option::Option<::std::string::String> {
        &self.primary_key_field
    }
    /// <p>The name of the field in which Amazon Bedrock stores the vector embeddings for your data sources.</p>
    /// This field is required.
    pub fn vector_field(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vector_field = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the field in which Amazon Bedrock stores the vector embeddings for your data sources.</p>
    pub fn set_vector_field(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vector_field = input;
        self
    }
    /// <p>The name of the field in which Amazon Bedrock stores the vector embeddings for your data sources.</p>
    pub fn get_vector_field(&self) -> &::std::option::Option<::std::string::String> {
        &self.vector_field
    }
    /// <p>The name of the field in which Amazon Bedrock stores the raw text from your data. The text is split according to the chunking strategy you choose.</p>
    /// This field is required.
    pub fn text_field(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text_field = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the field in which Amazon Bedrock stores the raw text from your data. The text is split according to the chunking strategy you choose.</p>
    pub fn set_text_field(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text_field = input;
        self
    }
    /// <p>The name of the field in which Amazon Bedrock stores the raw text from your data. The text is split according to the chunking strategy you choose.</p>
    pub fn get_text_field(&self) -> &::std::option::Option<::std::string::String> {
        &self.text_field
    }
    /// <p>The name of the field in which Amazon Bedrock stores metadata about the vector store.</p>
    /// This field is required.
    pub fn metadata_field(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metadata_field = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the field in which Amazon Bedrock stores metadata about the vector store.</p>
    pub fn set_metadata_field(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metadata_field = input;
        self
    }
    /// <p>The name of the field in which Amazon Bedrock stores metadata about the vector store.</p>
    pub fn get_metadata_field(&self) -> &::std::option::Option<::std::string::String> {
        &self.metadata_field
    }
    /// <p>Provide a name for the universal metadata field where Amazon Bedrock will store any custom metadata from your data source.</p>
    pub fn custom_metadata_field(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_metadata_field = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Provide a name for the universal metadata field where Amazon Bedrock will store any custom metadata from your data source.</p>
    pub fn set_custom_metadata_field(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_metadata_field = input;
        self
    }
    /// <p>Provide a name for the universal metadata field where Amazon Bedrock will store any custom metadata from your data source.</p>
    pub fn get_custom_metadata_field(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_metadata_field
    }
    /// Consumes the builder and constructs a [`RdsFieldMapping`](crate::types::RdsFieldMapping).
    /// This method will fail if any of the following fields are not set:
    /// - [`primary_key_field`](crate::types::builders::RdsFieldMappingBuilder::primary_key_field)
    /// - [`vector_field`](crate::types::builders::RdsFieldMappingBuilder::vector_field)
    /// - [`text_field`](crate::types::builders::RdsFieldMappingBuilder::text_field)
    /// - [`metadata_field`](crate::types::builders::RdsFieldMappingBuilder::metadata_field)
    pub fn build(self) -> ::std::result::Result<crate::types::RdsFieldMapping, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RdsFieldMapping {
            primary_key_field: self.primary_key_field.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "primary_key_field",
                    "primary_key_field was not specified but it is required when building RdsFieldMapping",
                )
            })?,
            vector_field: self.vector_field.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "vector_field",
                    "vector_field was not specified but it is required when building RdsFieldMapping",
                )
            })?,
            text_field: self.text_field.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "text_field",
                    "text_field was not specified but it is required when building RdsFieldMapping",
                )
            })?,
            metadata_field: self.metadata_field.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "metadata_field",
                    "metadata_field was not specified but it is required when building RdsFieldMapping",
                )
            })?,
            custom_metadata_field: self.custom_metadata_field,
        })
    }
}
