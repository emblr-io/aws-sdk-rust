// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that specifies the data type of a property.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DataType {
    /// <p>The underlying type of the data type.</p>
    pub r#type: crate::types::Type,
    /// <p>The nested type in the data type.</p>
    pub nested_type: ::std::option::Option<::std::boxed::Box<crate::types::DataType>>,
    /// <p>The allowed values for this data type.</p>
    pub allowed_values: ::std::option::Option<::std::vec::Vec<crate::types::DataValue>>,
    /// <p>The unit of measure used in this data type.</p>
    pub unit_of_measure: ::std::option::Option<::std::string::String>,
    /// <p>A relationship that associates a component with another component.</p>
    pub relationship: ::std::option::Option<crate::types::Relationship>,
}
impl DataType {
    /// <p>The underlying type of the data type.</p>
    pub fn r#type(&self) -> &crate::types::Type {
        &self.r#type
    }
    /// <p>The nested type in the data type.</p>
    pub fn nested_type(&self) -> ::std::option::Option<&crate::types::DataType> {
        self.nested_type.as_deref()
    }
    /// <p>The allowed values for this data type.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.allowed_values.is_none()`.
    pub fn allowed_values(&self) -> &[crate::types::DataValue] {
        self.allowed_values.as_deref().unwrap_or_default()
    }
    /// <p>The unit of measure used in this data type.</p>
    pub fn unit_of_measure(&self) -> ::std::option::Option<&str> {
        self.unit_of_measure.as_deref()
    }
    /// <p>A relationship that associates a component with another component.</p>
    pub fn relationship(&self) -> ::std::option::Option<&crate::types::Relationship> {
        self.relationship.as_ref()
    }
}
impl DataType {
    /// Creates a new builder-style object to manufacture [`DataType`](crate::types::DataType).
    pub fn builder() -> crate::types::builders::DataTypeBuilder {
        crate::types::builders::DataTypeBuilder::default()
    }
}

/// A builder for [`DataType`](crate::types::DataType).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DataTypeBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::Type>,
    pub(crate) nested_type: ::std::option::Option<::std::boxed::Box<crate::types::DataType>>,
    pub(crate) allowed_values: ::std::option::Option<::std::vec::Vec<crate::types::DataValue>>,
    pub(crate) unit_of_measure: ::std::option::Option<::std::string::String>,
    pub(crate) relationship: ::std::option::Option<crate::types::Relationship>,
}
impl DataTypeBuilder {
    /// <p>The underlying type of the data type.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::Type) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The underlying type of the data type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::Type>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The underlying type of the data type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::Type> {
        &self.r#type
    }
    /// <p>The nested type in the data type.</p>
    pub fn nested_type(mut self, input: impl ::std::convert::Into<::std::boxed::Box<crate::types::DataType>>) -> Self {
        self.nested_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The nested type in the data type.</p>
    pub fn set_nested_type(mut self, input: ::std::option::Option<::std::boxed::Box<crate::types::DataType>>) -> Self {
        self.nested_type = input;
        self
    }
    /// <p>The nested type in the data type.</p>
    pub fn get_nested_type(&self) -> &::std::option::Option<::std::boxed::Box<crate::types::DataType>> {
        &self.nested_type
    }
    /// Appends an item to `allowed_values`.
    ///
    /// To override the contents of this collection use [`set_allowed_values`](Self::set_allowed_values).
    ///
    /// <p>The allowed values for this data type.</p>
    pub fn allowed_values(mut self, input: crate::types::DataValue) -> Self {
        let mut v = self.allowed_values.unwrap_or_default();
        v.push(input);
        self.allowed_values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The allowed values for this data type.</p>
    pub fn set_allowed_values(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataValue>>) -> Self {
        self.allowed_values = input;
        self
    }
    /// <p>The allowed values for this data type.</p>
    pub fn get_allowed_values(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataValue>> {
        &self.allowed_values
    }
    /// <p>The unit of measure used in this data type.</p>
    pub fn unit_of_measure(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.unit_of_measure = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unit of measure used in this data type.</p>
    pub fn set_unit_of_measure(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.unit_of_measure = input;
        self
    }
    /// <p>The unit of measure used in this data type.</p>
    pub fn get_unit_of_measure(&self) -> &::std::option::Option<::std::string::String> {
        &self.unit_of_measure
    }
    /// <p>A relationship that associates a component with another component.</p>
    pub fn relationship(mut self, input: crate::types::Relationship) -> Self {
        self.relationship = ::std::option::Option::Some(input);
        self
    }
    /// <p>A relationship that associates a component with another component.</p>
    pub fn set_relationship(mut self, input: ::std::option::Option<crate::types::Relationship>) -> Self {
        self.relationship = input;
        self
    }
    /// <p>A relationship that associates a component with another component.</p>
    pub fn get_relationship(&self) -> &::std::option::Option<crate::types::Relationship> {
        &self.relationship
    }
    /// Consumes the builder and constructs a [`DataType`](crate::types::DataType).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::DataTypeBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::DataType, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DataType {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building DataType",
                )
            })?,
            nested_type: self.nested_type,
            allowed_values: self.allowed_values,
            unit_of_measure: self.unit_of_measure,
            relationship: self.relationship,
        })
    }
}
