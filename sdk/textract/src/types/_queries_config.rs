// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueriesConfig {
    /// <p></p>
    pub queries: ::std::vec::Vec<crate::types::Query>,
}
impl QueriesConfig {
    /// <p></p>
    pub fn queries(&self) -> &[crate::types::Query] {
        use std::ops::Deref;
        self.queries.deref()
    }
}
impl QueriesConfig {
    /// Creates a new builder-style object to manufacture [`QueriesConfig`](crate::types::QueriesConfig).
    pub fn builder() -> crate::types::builders::QueriesConfigBuilder {
        crate::types::builders::QueriesConfigBuilder::default()
    }
}

/// A builder for [`QueriesConfig`](crate::types::QueriesConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueriesConfigBuilder {
    pub(crate) queries: ::std::option::Option<::std::vec::Vec<crate::types::Query>>,
}
impl QueriesConfigBuilder {
    /// Appends an item to `queries`.
    ///
    /// To override the contents of this collection use [`set_queries`](Self::set_queries).
    ///
    /// <p></p>
    pub fn queries(mut self, input: crate::types::Query) -> Self {
        let mut v = self.queries.unwrap_or_default();
        v.push(input);
        self.queries = ::std::option::Option::Some(v);
        self
    }
    /// <p></p>
    pub fn set_queries(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Query>>) -> Self {
        self.queries = input;
        self
    }
    /// <p></p>
    pub fn get_queries(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Query>> {
        &self.queries
    }
    /// Consumes the builder and constructs a [`QueriesConfig`](crate::types::QueriesConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`queries`](crate::types::builders::QueriesConfigBuilder::queries)
    pub fn build(self) -> ::std::result::Result<crate::types::QueriesConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::QueriesConfig {
            queries: self.queries.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "queries",
                    "queries was not specified but it is required when building QueriesConfig",
                )
            })?,
        })
    }
}
