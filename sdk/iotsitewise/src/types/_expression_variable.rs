// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains expression variable information.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExpressionVariable {
    /// <p>The friendly name of the variable to be used in the expression.</p>
    pub name: ::std::string::String,
    /// <p>The variable that identifies an asset property from which to use values.</p>
    pub value: ::std::option::Option<crate::types::VariableValue>,
}
impl ExpressionVariable {
    /// <p>The friendly name of the variable to be used in the expression.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The variable that identifies an asset property from which to use values.</p>
    pub fn value(&self) -> ::std::option::Option<&crate::types::VariableValue> {
        self.value.as_ref()
    }
}
impl ExpressionVariable {
    /// Creates a new builder-style object to manufacture [`ExpressionVariable`](crate::types::ExpressionVariable).
    pub fn builder() -> crate::types::builders::ExpressionVariableBuilder {
        crate::types::builders::ExpressionVariableBuilder::default()
    }
}

/// A builder for [`ExpressionVariable`](crate::types::ExpressionVariable).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExpressionVariableBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<crate::types::VariableValue>,
}
impl ExpressionVariableBuilder {
    /// <p>The friendly name of the variable to be used in the expression.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The friendly name of the variable to be used in the expression.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The friendly name of the variable to be used in the expression.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The variable that identifies an asset property from which to use values.</p>
    /// This field is required.
    pub fn value(mut self, input: crate::types::VariableValue) -> Self {
        self.value = ::std::option::Option::Some(input);
        self
    }
    /// <p>The variable that identifies an asset property from which to use values.</p>
    pub fn set_value(mut self, input: ::std::option::Option<crate::types::VariableValue>) -> Self {
        self.value = input;
        self
    }
    /// <p>The variable that identifies an asset property from which to use values.</p>
    pub fn get_value(&self) -> &::std::option::Option<crate::types::VariableValue> {
        &self.value
    }
    /// Consumes the builder and constructs a [`ExpressionVariable`](crate::types::ExpressionVariable).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::ExpressionVariableBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::ExpressionVariable, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ExpressionVariable {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building ExpressionVariable",
                )
            })?,
            value: self.value,
        })
    }
}
