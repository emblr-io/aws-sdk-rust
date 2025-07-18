// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Lists network function instance metadata.</p>
/// <p>A network function instance is a function in a function package .</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSolFunctionInstanceMetadata {
    /// <p>When the network function instance was created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>When the network function instance was last modified.</p>
    pub last_modified: ::aws_smithy_types::DateTime,
}
impl ListSolFunctionInstanceMetadata {
    /// <p>When the network function instance was created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>When the network function instance was last modified.</p>
    pub fn last_modified(&self) -> &::aws_smithy_types::DateTime {
        &self.last_modified
    }
}
impl ListSolFunctionInstanceMetadata {
    /// Creates a new builder-style object to manufacture [`ListSolFunctionInstanceMetadata`](crate::types::ListSolFunctionInstanceMetadata).
    pub fn builder() -> crate::types::builders::ListSolFunctionInstanceMetadataBuilder {
        crate::types::builders::ListSolFunctionInstanceMetadataBuilder::default()
    }
}

/// A builder for [`ListSolFunctionInstanceMetadata`](crate::types::ListSolFunctionInstanceMetadata).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSolFunctionInstanceMetadataBuilder {
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_modified: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ListSolFunctionInstanceMetadataBuilder {
    /// <p>When the network function instance was created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the network function instance was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>When the network function instance was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>When the network function instance was last modified.</p>
    /// This field is required.
    pub fn last_modified(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_modified = ::std::option::Option::Some(input);
        self
    }
    /// <p>When the network function instance was last modified.</p>
    pub fn set_last_modified(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_modified = input;
        self
    }
    /// <p>When the network function instance was last modified.</p>
    pub fn get_last_modified(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_modified
    }
    /// Consumes the builder and constructs a [`ListSolFunctionInstanceMetadata`](crate::types::ListSolFunctionInstanceMetadata).
    /// This method will fail if any of the following fields are not set:
    /// - [`created_at`](crate::types::builders::ListSolFunctionInstanceMetadataBuilder::created_at)
    /// - [`last_modified`](crate::types::builders::ListSolFunctionInstanceMetadataBuilder::last_modified)
    pub fn build(self) -> ::std::result::Result<crate::types::ListSolFunctionInstanceMetadata, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ListSolFunctionInstanceMetadata {
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building ListSolFunctionInstanceMetadata",
                )
            })?,
            last_modified: self.last_modified.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified",
                    "last_modified was not specified but it is required when building ListSolFunctionInstanceMetadata",
                )
            })?,
        })
    }
}
