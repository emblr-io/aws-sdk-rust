// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A dimension is a name/value pair that is part of the identity of a metric. Because dimensions are part of the unique identifier for a metric, whenever you add a unique name/value pair to one of your metrics, you are creating a new variation of that metric. For example, many Amazon EC2 metrics publish <code>InstanceId</code> as a dimension name, and the actual instance ID as the value for that dimension.</p>
/// <p>You can assign up to 30 dimensions to a metric.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Dimension {
    /// <p>The name of the dimension. Dimension names must contain only ASCII characters, must include at least one non-whitespace character, and cannot start with a colon (<code>:</code>). ASCII control characters are not supported as part of dimension names.</p>
    pub name: ::std::string::String,
    /// <p>The value of the dimension. Dimension values must contain only ASCII characters and must include at least one non-whitespace character. ASCII control characters are not supported as part of dimension values.</p>
    pub value: ::std::string::String,
}
impl Dimension {
    /// <p>The name of the dimension. Dimension names must contain only ASCII characters, must include at least one non-whitespace character, and cannot start with a colon (<code>:</code>). ASCII control characters are not supported as part of dimension names.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The value of the dimension. Dimension values must contain only ASCII characters and must include at least one non-whitespace character. ASCII control characters are not supported as part of dimension values.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl Dimension {
    /// Creates a new builder-style object to manufacture [`Dimension`](crate::types::Dimension).
    pub fn builder() -> crate::types::builders::DimensionBuilder {
        crate::types::builders::DimensionBuilder::default()
    }
}

/// A builder for [`Dimension`](crate::types::Dimension).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DimensionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl DimensionBuilder {
    /// <p>The name of the dimension. Dimension names must contain only ASCII characters, must include at least one non-whitespace character, and cannot start with a colon (<code>:</code>). ASCII control characters are not supported as part of dimension names.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the dimension. Dimension names must contain only ASCII characters, must include at least one non-whitespace character, and cannot start with a colon (<code>:</code>). ASCII control characters are not supported as part of dimension names.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the dimension. Dimension names must contain only ASCII characters, must include at least one non-whitespace character, and cannot start with a colon (<code>:</code>). ASCII control characters are not supported as part of dimension names.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The value of the dimension. Dimension values must contain only ASCII characters and must include at least one non-whitespace character. ASCII control characters are not supported as part of dimension values.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value of the dimension. Dimension values must contain only ASCII characters and must include at least one non-whitespace character. ASCII control characters are not supported as part of dimension values.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value of the dimension. Dimension values must contain only ASCII characters and must include at least one non-whitespace character. ASCII control characters are not supported as part of dimension values.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`Dimension`](crate::types::Dimension).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::DimensionBuilder::name)
    /// - [`value`](crate::types::builders::DimensionBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::Dimension, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Dimension {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building Dimension",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building Dimension",
                )
            })?,
        })
    }
}
