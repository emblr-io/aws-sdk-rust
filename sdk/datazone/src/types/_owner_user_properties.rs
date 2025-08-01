// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The properties of the owner user.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OwnerUserProperties {
    /// <p>The ID of the owner user.</p>
    pub user_identifier: ::std::string::String,
}
impl OwnerUserProperties {
    /// <p>The ID of the owner user.</p>
    pub fn user_identifier(&self) -> &str {
        use std::ops::Deref;
        self.user_identifier.deref()
    }
}
impl OwnerUserProperties {
    /// Creates a new builder-style object to manufacture [`OwnerUserProperties`](crate::types::OwnerUserProperties).
    pub fn builder() -> crate::types::builders::OwnerUserPropertiesBuilder {
        crate::types::builders::OwnerUserPropertiesBuilder::default()
    }
}

/// A builder for [`OwnerUserProperties`](crate::types::OwnerUserProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OwnerUserPropertiesBuilder {
    pub(crate) user_identifier: ::std::option::Option<::std::string::String>,
}
impl OwnerUserPropertiesBuilder {
    /// <p>The ID of the owner user.</p>
    /// This field is required.
    pub fn user_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the owner user.</p>
    pub fn set_user_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_identifier = input;
        self
    }
    /// <p>The ID of the owner user.</p>
    pub fn get_user_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_identifier
    }
    /// Consumes the builder and constructs a [`OwnerUserProperties`](crate::types::OwnerUserProperties).
    /// This method will fail if any of the following fields are not set:
    /// - [`user_identifier`](crate::types::builders::OwnerUserPropertiesBuilder::user_identifier)
    pub fn build(self) -> ::std::result::Result<crate::types::OwnerUserProperties, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OwnerUserProperties {
            user_identifier: self.user_identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "user_identifier",
                    "user_identifier was not specified but it is required when building OwnerUserProperties",
                )
            })?,
        })
    }
}
