// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The criteria that a specific object attribute must meet to trigger the destination.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ObjectAttribute {
    /// <p>An attribute contained within a source object.</p>
    pub source: ::std::option::Option<::std::string::String>,
    /// <p>A field defined within an object type.</p>
    pub field_name: ::std::option::Option<::std::string::String>,
    /// <p>The operator used to compare an attribute against a list of values.</p>
    pub comparison_operator: crate::types::ComparisonOperator,
    /// <p>A list of attribute values used for comparison.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl ObjectAttribute {
    /// <p>An attribute contained within a source object.</p>
    pub fn source(&self) -> ::std::option::Option<&str> {
        self.source.as_deref()
    }
    /// <p>A field defined within an object type.</p>
    pub fn field_name(&self) -> ::std::option::Option<&str> {
        self.field_name.as_deref()
    }
    /// <p>The operator used to compare an attribute against a list of values.</p>
    pub fn comparison_operator(&self) -> &crate::types::ComparisonOperator {
        &self.comparison_operator
    }
    /// <p>A list of attribute values used for comparison.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl ObjectAttribute {
    /// Creates a new builder-style object to manufacture [`ObjectAttribute`](crate::types::ObjectAttribute).
    pub fn builder() -> crate::types::builders::ObjectAttributeBuilder {
        crate::types::builders::ObjectAttributeBuilder::default()
    }
}

/// A builder for [`ObjectAttribute`](crate::types::ObjectAttribute).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ObjectAttributeBuilder {
    pub(crate) source: ::std::option::Option<::std::string::String>,
    pub(crate) field_name: ::std::option::Option<::std::string::String>,
    pub(crate) comparison_operator: ::std::option::Option<crate::types::ComparisonOperator>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ObjectAttributeBuilder {
    /// <p>An attribute contained within a source object.</p>
    pub fn source(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An attribute contained within a source object.</p>
    pub fn set_source(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source = input;
        self
    }
    /// <p>An attribute contained within a source object.</p>
    pub fn get_source(&self) -> &::std::option::Option<::std::string::String> {
        &self.source
    }
    /// <p>A field defined within an object type.</p>
    pub fn field_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.field_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A field defined within an object type.</p>
    pub fn set_field_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.field_name = input;
        self
    }
    /// <p>A field defined within an object type.</p>
    pub fn get_field_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.field_name
    }
    /// <p>The operator used to compare an attribute against a list of values.</p>
    /// This field is required.
    pub fn comparison_operator(mut self, input: crate::types::ComparisonOperator) -> Self {
        self.comparison_operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operator used to compare an attribute against a list of values.</p>
    pub fn set_comparison_operator(mut self, input: ::std::option::Option<crate::types::ComparisonOperator>) -> Self {
        self.comparison_operator = input;
        self
    }
    /// <p>The operator used to compare an attribute against a list of values.</p>
    pub fn get_comparison_operator(&self) -> &::std::option::Option<crate::types::ComparisonOperator> {
        &self.comparison_operator
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>A list of attribute values used for comparison.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of attribute values used for comparison.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>A list of attribute values used for comparison.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`ObjectAttribute`](crate::types::ObjectAttribute).
    /// This method will fail if any of the following fields are not set:
    /// - [`comparison_operator`](crate::types::builders::ObjectAttributeBuilder::comparison_operator)
    /// - [`values`](crate::types::builders::ObjectAttributeBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::ObjectAttribute, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ObjectAttribute {
            source: self.source,
            field_name: self.field_name,
            comparison_operator: self.comparison_operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "comparison_operator",
                    "comparison_operator was not specified but it is required when building ObjectAttribute",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building ObjectAttribute",
                )
            })?,
        })
    }
}
