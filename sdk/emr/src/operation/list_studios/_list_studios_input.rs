// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListStudiosInput {
    /// <p>The pagination token that indicates the set of results to retrieve.</p>
    pub marker: ::std::option::Option<::std::string::String>,
}
impl ListStudiosInput {
    /// <p>The pagination token that indicates the set of results to retrieve.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ListStudiosInput {
    /// Creates a new builder-style object to manufacture [`ListStudiosInput`](crate::operation::list_studios::ListStudiosInput).
    pub fn builder() -> crate::operation::list_studios::builders::ListStudiosInputBuilder {
        crate::operation::list_studios::builders::ListStudiosInputBuilder::default()
    }
}

/// A builder for [`ListStudiosInput`](crate::operation::list_studios::ListStudiosInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListStudiosInputBuilder {
    pub(crate) marker: ::std::option::Option<::std::string::String>,
}
impl ListStudiosInputBuilder {
    /// <p>The pagination token that indicates the set of results to retrieve.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that indicates the set of results to retrieve.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The pagination token that indicates the set of results to retrieve.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    /// Consumes the builder and constructs a [`ListStudiosInput`](crate::operation::list_studios::ListStudiosInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_studios::ListStudiosInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_studios::ListStudiosInput { marker: self.marker })
    }
}
