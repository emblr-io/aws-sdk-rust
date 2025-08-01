// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing the query parameter to match.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueryParameterMatch {
    /// <p>The exact query parameter to match on.</p>
    pub exact: ::std::option::Option<::std::string::String>,
}
impl QueryParameterMatch {
    /// <p>The exact query parameter to match on.</p>
    pub fn exact(&self) -> ::std::option::Option<&str> {
        self.exact.as_deref()
    }
}
impl QueryParameterMatch {
    /// Creates a new builder-style object to manufacture [`QueryParameterMatch`](crate::types::QueryParameterMatch).
    pub fn builder() -> crate::types::builders::QueryParameterMatchBuilder {
        crate::types::builders::QueryParameterMatchBuilder::default()
    }
}

/// A builder for [`QueryParameterMatch`](crate::types::QueryParameterMatch).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueryParameterMatchBuilder {
    pub(crate) exact: ::std::option::Option<::std::string::String>,
}
impl QueryParameterMatchBuilder {
    /// <p>The exact query parameter to match on.</p>
    pub fn exact(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.exact = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The exact query parameter to match on.</p>
    pub fn set_exact(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.exact = input;
        self
    }
    /// <p>The exact query parameter to match on.</p>
    pub fn get_exact(&self) -> &::std::option::Option<::std::string::String> {
        &self.exact
    }
    /// Consumes the builder and constructs a [`QueryParameterMatch`](crate::types::QueryParameterMatch).
    pub fn build(self) -> crate::types::QueryParameterMatch {
        crate::types::QueryParameterMatch { exact: self.exact }
    }
}
