// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A filter name and value pair that is used to return more specific results from a describe or list operation. You can use filters can be used to match a set of resources by specific criteria, such as tags, attributes, or IDs.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Filter {
    /// <p>The name of an attribute to use as a filter.</p>
    pub attribute: ::std::option::Option<::std::string::String>,
    /// <p>The type of search (For example, eq, geq, leq)</p>
    pub operation: ::std::option::Option<::std::string::String>,
    /// <p>Value of the filter.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl Filter {
    /// <p>The name of an attribute to use as a filter.</p>
    pub fn attribute(&self) -> ::std::option::Option<&str> {
        self.attribute.as_deref()
    }
    /// <p>The type of search (For example, eq, geq, leq)</p>
    pub fn operation(&self) -> ::std::option::Option<&str> {
        self.operation.as_deref()
    }
    /// <p>Value of the filter.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl Filter {
    /// Creates a new builder-style object to manufacture [`Filter`](crate::types::Filter).
    pub fn builder() -> crate::types::builders::FilterBuilder {
        crate::types::builders::FilterBuilder::default()
    }
}

/// A builder for [`Filter`](crate::types::Filter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FilterBuilder {
    pub(crate) attribute: ::std::option::Option<::std::string::String>,
    pub(crate) operation: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl FilterBuilder {
    /// <p>The name of an attribute to use as a filter.</p>
    pub fn attribute(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of an attribute to use as a filter.</p>
    pub fn set_attribute(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute = input;
        self
    }
    /// <p>The name of an attribute to use as a filter.</p>
    pub fn get_attribute(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute
    }
    /// <p>The type of search (For example, eq, geq, leq)</p>
    pub fn operation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.operation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of search (For example, eq, geq, leq)</p>
    pub fn set_operation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.operation = input;
        self
    }
    /// <p>The type of search (For example, eq, geq, leq)</p>
    pub fn get_operation(&self) -> &::std::option::Option<::std::string::String> {
        &self.operation
    }
    /// <p>Value of the filter.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Value of the filter.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>Value of the filter.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`Filter`](crate::types::Filter).
    pub fn build(self) -> crate::types::Filter {
        crate::types::Filter {
            attribute: self.attribute,
            operation: self.operation,
            value: self.value,
        }
    }
}
