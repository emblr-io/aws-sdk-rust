// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The dynamic value of the resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceValue {
    /// <p>The value is a resource ID.</p>
    pub value: crate::types::ResourceValueType,
}
impl ResourceValue {
    /// <p>The value is a resource ID.</p>
    pub fn value(&self) -> &crate::types::ResourceValueType {
        &self.value
    }
}
impl ResourceValue {
    /// Creates a new builder-style object to manufacture [`ResourceValue`](crate::types::ResourceValue).
    pub fn builder() -> crate::types::builders::ResourceValueBuilder {
        crate::types::builders::ResourceValueBuilder::default()
    }
}

/// A builder for [`ResourceValue`](crate::types::ResourceValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceValueBuilder {
    pub(crate) value: ::std::option::Option<crate::types::ResourceValueType>,
}
impl ResourceValueBuilder {
    /// <p>The value is a resource ID.</p>
    /// This field is required.
    pub fn value(mut self, input: crate::types::ResourceValueType) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value is a resource ID.</p>
    pub fn set_value(mut self, input: ::std::option::Option<crate::types::ResourceValueType>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value is a resource ID.</p>
    pub fn get_value(&self) -> &::std::option::Option<crate::types::ResourceValueType> {
        &self.value
    }
    /// Consumes the builder and constructs a [`ResourceValue`](crate::types::ResourceValue).
    /// This method will fail if any of the following fields are not set:
    /// - [`value`](crate::types::builders::ResourceValueBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::ResourceValue, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ResourceValue {
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building ResourceValue",
                )
            })?,
        })
    }
}
