// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for Twitter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TwitterParameters {
    /// <p>Twitter query string.</p>
    pub query: ::std::string::String,
    /// <p>Maximum number of rows to query Twitter.</p>
    pub max_rows: i32,
}
impl TwitterParameters {
    /// <p>Twitter query string.</p>
    pub fn query(&self) -> &str {
        use std::ops::Deref;
        self.query.deref()
    }
    /// <p>Maximum number of rows to query Twitter.</p>
    pub fn max_rows(&self) -> i32 {
        self.max_rows
    }
}
impl TwitterParameters {
    /// Creates a new builder-style object to manufacture [`TwitterParameters`](crate::types::TwitterParameters).
    pub fn builder() -> crate::types::builders::TwitterParametersBuilder {
        crate::types::builders::TwitterParametersBuilder::default()
    }
}

/// A builder for [`TwitterParameters`](crate::types::TwitterParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TwitterParametersBuilder {
    pub(crate) query: ::std::option::Option<::std::string::String>,
    pub(crate) max_rows: ::std::option::Option<i32>,
}
impl TwitterParametersBuilder {
    /// <p>Twitter query string.</p>
    /// This field is required.
    pub fn query(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.query = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Twitter query string.</p>
    pub fn set_query(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.query = input;
        self
    }
    /// <p>Twitter query string.</p>
    pub fn get_query(&self) -> &::std::option::Option<::std::string::String> {
        &self.query
    }
    /// <p>Maximum number of rows to query Twitter.</p>
    /// This field is required.
    pub fn max_rows(mut self, input: i32) -> Self {
        self.max_rows = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of rows to query Twitter.</p>
    pub fn set_max_rows(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_rows = input;
        self
    }
    /// <p>Maximum number of rows to query Twitter.</p>
    pub fn get_max_rows(&self) -> &::std::option::Option<i32> {
        &self.max_rows
    }
    /// Consumes the builder and constructs a [`TwitterParameters`](crate::types::TwitterParameters).
    /// This method will fail if any of the following fields are not set:
    /// - [`query`](crate::types::builders::TwitterParametersBuilder::query)
    /// - [`max_rows`](crate::types::builders::TwitterParametersBuilder::max_rows)
    pub fn build(self) -> ::std::result::Result<crate::types::TwitterParameters, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TwitterParameters {
            query: self.query.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "query",
                    "query was not specified but it is required when building TwitterParameters",
                )
            })?,
            max_rows: self.max_rows.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "max_rows",
                    "max_rows was not specified but it is required when building TwitterParameters",
                )
            })?,
        })
    }
}
