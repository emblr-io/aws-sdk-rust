// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The definition of a filter to filter the data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IngestionJobFilter {
    /// <p>The name of field or attribute to apply the filter.</p>
    pub attribute: crate::types::IngestionJobFilterAttribute,
    /// <p>The operation to apply to the field or attribute.</p>
    pub operator: crate::types::IngestionJobFilterOperator,
    /// <p>A list of values that belong to the field or attribute.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl IngestionJobFilter {
    /// <p>The name of field or attribute to apply the filter.</p>
    pub fn attribute(&self) -> &crate::types::IngestionJobFilterAttribute {
        &self.attribute
    }
    /// <p>The operation to apply to the field or attribute.</p>
    pub fn operator(&self) -> &crate::types::IngestionJobFilterOperator {
        &self.operator
    }
    /// <p>A list of values that belong to the field or attribute.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl IngestionJobFilter {
    /// Creates a new builder-style object to manufacture [`IngestionJobFilter`](crate::types::IngestionJobFilter).
    pub fn builder() -> crate::types::builders::IngestionJobFilterBuilder {
        crate::types::builders::IngestionJobFilterBuilder::default()
    }
}

/// A builder for [`IngestionJobFilter`](crate::types::IngestionJobFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IngestionJobFilterBuilder {
    pub(crate) attribute: ::std::option::Option<crate::types::IngestionJobFilterAttribute>,
    pub(crate) operator: ::std::option::Option<crate::types::IngestionJobFilterOperator>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl IngestionJobFilterBuilder {
    /// <p>The name of field or attribute to apply the filter.</p>
    /// This field is required.
    pub fn attribute(mut self, input: crate::types::IngestionJobFilterAttribute) -> Self {
        self.attribute = ::std::option::Option::Some(input);
        self
    }
    /// <p>The name of field or attribute to apply the filter.</p>
    pub fn set_attribute(mut self, input: ::std::option::Option<crate::types::IngestionJobFilterAttribute>) -> Self {
        self.attribute = input;
        self
    }
    /// <p>The name of field or attribute to apply the filter.</p>
    pub fn get_attribute(&self) -> &::std::option::Option<crate::types::IngestionJobFilterAttribute> {
        &self.attribute
    }
    /// <p>The operation to apply to the field or attribute.</p>
    /// This field is required.
    pub fn operator(mut self, input: crate::types::IngestionJobFilterOperator) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operation to apply to the field or attribute.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::IngestionJobFilterOperator>) -> Self {
        self.operator = input;
        self
    }
    /// <p>The operation to apply to the field or attribute.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::IngestionJobFilterOperator> {
        &self.operator
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>A list of values that belong to the field or attribute.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of values that belong to the field or attribute.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>A list of values that belong to the field or attribute.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`IngestionJobFilter`](crate::types::IngestionJobFilter).
    /// This method will fail if any of the following fields are not set:
    /// - [`attribute`](crate::types::builders::IngestionJobFilterBuilder::attribute)
    /// - [`operator`](crate::types::builders::IngestionJobFilterBuilder::operator)
    /// - [`values`](crate::types::builders::IngestionJobFilterBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::IngestionJobFilter, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IngestionJobFilter {
            attribute: self.attribute.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute",
                    "attribute was not specified but it is required when building IngestionJobFilter",
                )
            })?,
            operator: self.operator.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "operator",
                    "operator was not specified but it is required when building IngestionJobFilter",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building IngestionJobFilter",
                )
            })?,
        })
    }
}
