// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object for case field values.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FieldValue {
    /// <p>Unique identifier of a field.</p>
    pub id: ::std::string::String,
    /// <p>Union of potential field value types.</p>
    pub value: ::std::option::Option<crate::types::FieldValueUnion>,
}
impl FieldValue {
    /// <p>Unique identifier of a field.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>Union of potential field value types.</p>
    pub fn value(&self) -> ::std::option::Option<&crate::types::FieldValueUnion> {
        self.value.as_ref()
    }
}
impl FieldValue {
    /// Creates a new builder-style object to manufacture [`FieldValue`](crate::types::FieldValue).
    pub fn builder() -> crate::types::builders::FieldValueBuilder {
        crate::types::builders::FieldValueBuilder::default()
    }
}

/// A builder for [`FieldValue`](crate::types::FieldValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FieldValueBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<crate::types::FieldValueUnion>,
}
impl FieldValueBuilder {
    /// <p>Unique identifier of a field.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifier of a field.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>Unique identifier of a field.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>Union of potential field value types.</p>
    /// This field is required.
    pub fn value(mut self, input: crate::types::FieldValueUnion) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>Union of potential field value types.</p>
    pub fn set_value(mut self, input: ::std::option::Option<crate::types::FieldValueUnion>) -> Self {
        self.value = input;
        self
    }
    /// <p>Union of potential field value types.</p>
    pub fn get_value(&self) -> &::std::option::Option<crate::types::FieldValueUnion> {
        &self.value
    }
    /// Consumes the builder and constructs a [`FieldValue`](crate::types::FieldValue).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::FieldValueBuilder::id)
    pub fn build(self) -> ::std::result::Result<crate::types::FieldValue, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::FieldValue {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building FieldValue",
                )
            })?,
            value: self.value,
        })
    }
}
