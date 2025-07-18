// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A dimension name and value.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DimensionNameValue {
    /// <p>The name of the dimension.</p>
    pub dimension_name: ::std::string::String,
    /// <p>The value of the dimension.</p>
    pub dimension_value: ::std::string::String,
}
impl DimensionNameValue {
    /// <p>The name of the dimension.</p>
    pub fn dimension_name(&self) -> &str {
        use std::ops::Deref;
        self.dimension_name.deref()
    }
    /// <p>The value of the dimension.</p>
    pub fn dimension_value(&self) -> &str {
        use std::ops::Deref;
        self.dimension_value.deref()
    }
}
impl DimensionNameValue {
    /// Creates a new builder-style object to manufacture [`DimensionNameValue`](crate::types::DimensionNameValue).
    pub fn builder() -> crate::types::builders::DimensionNameValueBuilder {
        crate::types::builders::DimensionNameValueBuilder::default()
    }
}

/// A builder for [`DimensionNameValue`](crate::types::DimensionNameValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DimensionNameValueBuilder {
    pub(crate) dimension_name: ::std::option::Option<::std::string::String>,
    pub(crate) dimension_value: ::std::option::Option<::std::string::String>,
}
impl DimensionNameValueBuilder {
    /// <p>The name of the dimension.</p>
    /// This field is required.
    pub fn dimension_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dimension_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dimension.</p>
    pub fn set_dimension_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dimension_name = input;
        self
    }
    /// <p>The name of the dimension.</p>
    pub fn get_dimension_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.dimension_name
    }
    /// <p>The value of the dimension.</p>
    /// This field is required.
    pub fn dimension_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.dimension_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the dimension.</p>
    pub fn set_dimension_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.dimension_value = input;
        self
    }
    /// <p>The value of the dimension.</p>
    pub fn get_dimension_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.dimension_value
    }
    /// Consumes the builder and constructs a [`DimensionNameValue`](crate::types::DimensionNameValue).
    /// This method will fail if any of the following fields are not set:
    /// - [`dimension_name`](crate::types::builders::DimensionNameValueBuilder::dimension_name)
    /// - [`dimension_value`](crate::types::builders::DimensionNameValueBuilder::dimension_value)
    pub fn build(self) -> ::std::result::Result<crate::types::DimensionNameValue, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DimensionNameValue {
            dimension_name: self.dimension_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dimension_name",
                    "dimension_name was not specified but it is required when building DimensionNameValue",
                )
            })?,
            dimension_value: self.dimension_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "dimension_value",
                    "dimension_value was not specified but it is required when building DimensionNameValue",
                )
            })?,
        })
    }
}
