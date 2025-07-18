// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure representing the datatype of the value.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Datatype {
    /// <p>The datatype of the value.</p>
    pub id: ::std::string::String,
    /// <p>A label assigned to the datatype.</p>
    pub label: ::std::string::String,
}
impl Datatype {
    /// <p>The datatype of the value.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>A label assigned to the datatype.</p>
    pub fn label(&self) -> &str {
        use std::ops::Deref;
        self.label.deref()
    }
}
impl Datatype {
    /// Creates a new builder-style object to manufacture [`Datatype`](crate::types::Datatype).
    pub fn builder() -> crate::types::builders::DatatypeBuilder {
        crate::types::builders::DatatypeBuilder::default()
    }
}

/// A builder for [`Datatype`](crate::types::Datatype).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DatatypeBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) label: ::std::option::Option<::std::string::String>,
}
impl DatatypeBuilder {
    /// <p>The datatype of the value.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The datatype of the value.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The datatype of the value.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A label assigned to the datatype.</p>
    /// This field is required.
    pub fn label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A label assigned to the datatype.</p>
    pub fn set_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.label = input;
        self
    }
    /// <p>A label assigned to the datatype.</p>
    pub fn get_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.label
    }
    /// Consumes the builder and constructs a [`Datatype`](crate::types::Datatype).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::DatatypeBuilder::id)
    /// - [`label`](crate::types::builders::DatatypeBuilder::label)
    pub fn build(self) -> ::std::result::Result<crate::types::Datatype, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Datatype {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building Datatype",
                )
            })?,
            label: self.label.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "label",
                    "label was not specified but it is required when building Datatype",
                )
            })?,
        })
    }
}
