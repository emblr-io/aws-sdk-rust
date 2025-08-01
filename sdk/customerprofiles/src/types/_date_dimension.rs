// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object that segments on various Customer Profile's date fields.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DateDimension {
    /// <p>The action to segment with.</p>
    pub dimension_type: crate::types::DateDimensionType,
    /// <p>The values to apply the DimensionType on.</p>
    pub values: ::std::vec::Vec<::std::string::String>,
}
impl DateDimension {
    /// <p>The action to segment with.</p>
    pub fn dimension_type(&self) -> &crate::types::DateDimensionType {
        &self.dimension_type
    }
    /// <p>The values to apply the DimensionType on.</p>
    pub fn values(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.values.deref()
    }
}
impl DateDimension {
    /// Creates a new builder-style object to manufacture [`DateDimension`](crate::types::DateDimension).
    pub fn builder() -> crate::types::builders::DateDimensionBuilder {
        crate::types::builders::DateDimensionBuilder::default()
    }
}

/// A builder for [`DateDimension`](crate::types::DateDimension).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DateDimensionBuilder {
    pub(crate) dimension_type: ::std::option::Option<crate::types::DateDimensionType>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DateDimensionBuilder {
    /// <p>The action to segment with.</p>
    /// This field is required.
    pub fn dimension_type(mut self, input: crate::types::DateDimensionType) -> Self {
        self.dimension_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The action to segment with.</p>
    pub fn set_dimension_type(mut self, input: ::std::option::Option<crate::types::DateDimensionType>) -> Self {
        self.dimension_type = input;
        self
    }
    /// <p>The action to segment with.</p>
    pub fn get_dimension_type(&self) -> &::std::option::Option<crate::types::DateDimensionType> {
        &self.dimension_type
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>The values to apply the DimensionType on.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>The values to apply the DimensionType on.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>The values to apply the DimensionType on.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// Consumes the builder and constructs a [`DateDimension`](crate::types::DateDimension).
    /// This method will fail if any of the following fields are not set:
    /// - [`dimension_type`](crate::types::builders::DateDimensionBuilder::dimension_type)
    /// - [`values`](crate::types::builders::DateDimensionBuilder::values)
    pub fn build(self) -> ::std::result::Result<crate::types::DateDimension, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DateDimension {
            dimension_type: self.dimension_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dimension_type",
                    "dimension_type was not specified but it is required when building DateDimension",
                )
            })?,
            values: self.values.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "values",
                    "values was not specified but it is required when building DateDimension",
                )
            })?,
        })
    }
}
