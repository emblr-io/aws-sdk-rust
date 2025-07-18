// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The status that operation results are filtered by.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OperationResultFilter {
    /// <p>The type of filter to apply.</p>
    pub name: ::std::option::Option<crate::types::OperationResultFilterName>,
    /// <p>The value to filter by.</p>
    pub values: ::std::option::Option<::std::string::String>,
}
impl OperationResultFilter {
    /// <p>The type of filter to apply.</p>
    pub fn name(&self) -> ::std::option::Option<&crate::types::OperationResultFilterName> {
        self.name.as_ref()
    }
    /// <p>The value to filter by.</p>
    pub fn values(&self) -> ::std::option::Option<&str> {
        self.values.as_deref()
    }
}
impl OperationResultFilter {
    /// Creates a new builder-style object to manufacture [`OperationResultFilter`](crate::types::OperationResultFilter).
    pub fn builder() -> crate::types::builders::OperationResultFilterBuilder {
        crate::types::builders::OperationResultFilterBuilder::default()
    }
}

/// A builder for [`OperationResultFilter`](crate::types::OperationResultFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OperationResultFilterBuilder {
    pub(crate) name: ::std::option::Option<crate::types::OperationResultFilterName>,
    pub(crate) values: ::std::option::Option<::std::string::String>,
}
impl OperationResultFilterBuilder {
    /// <p>The type of filter to apply.</p>
    pub fn name(mut self, input: crate::types::OperationResultFilterName) -> Self {
        self.name = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of filter to apply.</p>
    pub fn set_name(mut self, input: ::std::option::Option<crate::types::OperationResultFilterName>) -> Self {
        self.name = input;
        self
    }
    /// <p>The type of filter to apply.</p>
    pub fn get_name(&self) -> &::std::option::Option<crate::types::OperationResultFilterName> {
        &self.name
    }
    /// <p>The value to filter by.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.values = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value to filter by.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.values = input;
        self
    }
    /// <p>The value to filter by.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::string::String> {
        &self.values
    }
    /// Consumes the builder and constructs a [`OperationResultFilter`](crate::types::OperationResultFilter).
    pub fn build(self) -> crate::types::OperationResultFilter {
        crate::types::OperationResultFilter {
            name: self.name,
            values: self.values,
        }
    }
}
