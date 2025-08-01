// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Neptune logs are converted to SPARQL quads in the graph using the Resource Description Framework (RDF) <a href="https://www.w3.org/TR/n-quads/">N-QUADS</a> language defined in the W3C RDF 1.1 N-Quads specification</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SparqlData {
    /// <p>Holds an <a href="https://www.w3.org/TR/n-quads/">N-QUADS</a> statement expressing the changed quad.</p>
    pub stmt: ::std::string::String,
}
impl SparqlData {
    /// <p>Holds an <a href="https://www.w3.org/TR/n-quads/">N-QUADS</a> statement expressing the changed quad.</p>
    pub fn stmt(&self) -> &str {
        use std::ops::Deref;
        self.stmt.deref()
    }
}
impl SparqlData {
    /// Creates a new builder-style object to manufacture [`SparqlData`](crate::types::SparqlData).
    pub fn builder() -> crate::types::builders::SparqlDataBuilder {
        crate::types::builders::SparqlDataBuilder::default()
    }
}

/// A builder for [`SparqlData`](crate::types::SparqlData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SparqlDataBuilder {
    pub(crate) stmt: ::std::option::Option<::std::string::String>,
}
impl SparqlDataBuilder {
    /// <p>Holds an <a href="https://www.w3.org/TR/n-quads/">N-QUADS</a> statement expressing the changed quad.</p>
    /// This field is required.
    pub fn stmt(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stmt = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Holds an <a href="https://www.w3.org/TR/n-quads/">N-QUADS</a> statement expressing the changed quad.</p>
    pub fn set_stmt(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stmt = input;
        self
    }
    /// <p>Holds an <a href="https://www.w3.org/TR/n-quads/">N-QUADS</a> statement expressing the changed quad.</p>
    pub fn get_stmt(&self) -> &::std::option::Option<::std::string::String> {
        &self.stmt
    }
    /// Consumes the builder and constructs a [`SparqlData`](crate::types::SparqlData).
    /// This method will fail if any of the following fields are not set:
    /// - [`stmt`](crate::types::builders::SparqlDataBuilder::stmt)
    pub fn build(self) -> ::std::result::Result<crate::types::SparqlData, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SparqlData {
            stmt: self.stmt.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "stmt",
                    "stmt was not specified but it is required when building SparqlData",
                )
            })?,
        })
    }
}
