// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A filter object that is used to return more specific results from a describe operation. Filters can be used to match a set of resources by specific criteria.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Filter {
    /// <p>The type of name to filter by.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>One or more values for the name to filter by.</p>
    pub values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An operator for filtering results.</p>
    pub operator: ::std::option::Option<crate::types::Operator>,
}
impl Filter {
    /// <p>The type of name to filter by.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>One or more values for the name to filter by.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.values.is_none()`.
    pub fn values(&self) -> &[::std::string::String] {
        self.values.as_deref().unwrap_or_default()
    }
    /// <p>An operator for filtering results.</p>
    pub fn operator(&self) -> ::std::option::Option<&crate::types::Operator> {
        self.operator.as_ref()
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
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) values: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) operator: ::std::option::Option<crate::types::Operator>,
}
impl FilterBuilder {
    /// <p>The type of name to filter by.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of name to filter by.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The type of name to filter by.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `values`.
    ///
    /// To override the contents of this collection use [`set_values`](Self::set_values).
    ///
    /// <p>One or more values for the name to filter by.</p>
    pub fn values(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.values.unwrap_or_default();
        v.push(input.into());
        self.values = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more values for the name to filter by.</p>
    pub fn set_values(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.values = input;
        self
    }
    /// <p>One or more values for the name to filter by.</p>
    pub fn get_values(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.values
    }
    /// <p>An operator for filtering results.</p>
    pub fn operator(mut self, input: crate::types::Operator) -> Self {
        self.operator = ::std::option::Option::Some(input);
        self
    }
    /// <p>An operator for filtering results.</p>
    pub fn set_operator(mut self, input: ::std::option::Option<crate::types::Operator>) -> Self {
        self.operator = input;
        self
    }
    /// <p>An operator for filtering results.</p>
    pub fn get_operator(&self) -> &::std::option::Option<crate::types::Operator> {
        &self.operator
    }
    /// Consumes the builder and constructs a [`Filter`](crate::types::Filter).
    pub fn build(self) -> crate::types::Filter {
        crate::types::Filter {
            name: self.name,
            values: self.values,
            operator: self.operator,
        }
    }
}
