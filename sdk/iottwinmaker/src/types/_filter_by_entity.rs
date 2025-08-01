// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Vilter by entity.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FilterByEntity {
    /// <p>The entity Id.</p>
    pub entity_id: ::std::string::String,
}
impl FilterByEntity {
    /// <p>The entity Id.</p>
    pub fn entity_id(&self) -> &str {
        use std::ops::Deref;
        self.entity_id.deref()
    }
}
impl FilterByEntity {
    /// Creates a new builder-style object to manufacture [`FilterByEntity`](crate::types::FilterByEntity).
    pub fn builder() -> crate::types::builders::FilterByEntityBuilder {
        crate::types::builders::FilterByEntityBuilder::default()
    }
}

/// A builder for [`FilterByEntity`](crate::types::FilterByEntity).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterByEntityBuilder {
    pub(crate) entity_id: ::std::option::Option<::std::string::String>,
}
impl FilterByEntityBuilder {
    /// <p>The entity Id.</p>
    /// This field is required.
    pub fn entity_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.entity_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The entity Id.</p>
    pub fn set_entity_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.entity_id = input;
        self
    }
    /// <p>The entity Id.</p>
    pub fn get_entity_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.entity_id
    }
    /// Consumes the builder and constructs a [`FilterByEntity`](crate::types::FilterByEntity).
    /// This method will fail if any of the following fields are not set:
    /// - [`entity_id`](crate::types::builders::FilterByEntityBuilder::entity_id)
    pub fn build(self) -> ::std::result::Result<crate::types::FilterByEntity, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FilterByEntity {
            entity_id: self.entity_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "entity_id",
                    "entity_id was not specified but it is required when building FilterByEntity",
                )
            })?,
        })
    }
}
