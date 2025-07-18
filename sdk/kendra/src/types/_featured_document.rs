// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A featured document. This document is displayed at the top of the search results page, placed above all other results for certain queries. If there's an exact match of a query, then the document is featured in the search results.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FeaturedDocument {
    /// <p>The identifier of the document to feature in the search results. You can use the <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Query.html">Query</a> API to search for specific documents with their document IDs included in the result items, or you can use the console.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl FeaturedDocument {
    /// <p>The identifier of the document to feature in the search results. You can use the <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Query.html">Query</a> API to search for specific documents with their document IDs included in the result items, or you can use the console.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl FeaturedDocument {
    /// Creates a new builder-style object to manufacture [`FeaturedDocument`](crate::types::FeaturedDocument).
    pub fn builder() -> crate::types::builders::FeaturedDocumentBuilder {
        crate::types::builders::FeaturedDocumentBuilder::default()
    }
}

/// A builder for [`FeaturedDocument`](crate::types::FeaturedDocument).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FeaturedDocumentBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl FeaturedDocumentBuilder {
    /// <p>The identifier of the document to feature in the search results. You can use the <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Query.html">Query</a> API to search for specific documents with their document IDs included in the result items, or you can use the console.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the document to feature in the search results. You can use the <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Query.html">Query</a> API to search for specific documents with their document IDs included in the result items, or you can use the console.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the document to feature in the search results. You can use the <a href="https://docs.aws.amazon.com/kendra/latest/dg/API_Query.html">Query</a> API to search for specific documents with their document IDs included in the result items, or you can use the console.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`FeaturedDocument`](crate::types::FeaturedDocument).
    pub fn build(self) -> crate::types::FeaturedDocument {
        crate::types::FeaturedDocument { id: self.id }
    }
}
