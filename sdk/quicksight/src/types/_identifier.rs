// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The definition for the identifier.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Identifier {
    /// <p>The identity of the identifier.</p>
    pub identity: ::std::string::String,
}
impl Identifier {
    /// <p>The identity of the identifier.</p>
    pub fn identity(&self) -> &str {
        use std::ops::Deref;
        self.identity.deref()
    }
}
impl Identifier {
    /// Creates a new builder-style object to manufacture [`Identifier`](crate::types::Identifier).
    pub fn builder() -> crate::types::builders::IdentifierBuilder {
        crate::types::builders::IdentifierBuilder::default()
    }
}

/// A builder for [`Identifier`](crate::types::Identifier).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IdentifierBuilder {
    pub(crate) identity: ::std::option::Option<::std::string::String>,
}
impl IdentifierBuilder {
    /// <p>The identity of the identifier.</p>
    /// This field is required.
    pub fn identity(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identity of the identifier.</p>
    pub fn set_identity(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity = input;
        self
    }
    /// <p>The identity of the identifier.</p>
    pub fn get_identity(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity
    }
    /// Consumes the builder and constructs a [`Identifier`](crate::types::Identifier).
    /// This method will fail if any of the following fields are not set:
    /// - [`identity`](crate::types::builders::IdentifierBuilder::identity)
    pub fn build(self) -> ::std::result::Result<crate::types::Identifier, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Identifier {
            identity: self.identity.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "identity",
                    "identity was not specified but it is required when building Identifier",
                )
            })?,
        })
    }
}
