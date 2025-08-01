// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Retrieves all available parent paths for any object type such as node, leaf node, policy node, and index node objects inside a <code>BatchRead</code> operation. For more information, see <code>ListObjectParentPaths</code> and <code>BatchReadRequest$Operations</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchListObjectParentPaths {
    /// <p>The reference that identifies the object whose attributes will be listed.</p>
    pub object_reference: ::std::option::Option<crate::types::ObjectReference>,
    /// <p>The pagination token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to retrieve.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl BatchListObjectParentPaths {
    /// <p>The reference that identifies the object whose attributes will be listed.</p>
    pub fn object_reference(&self) -> ::std::option::Option<&crate::types::ObjectReference> {
        self.object_reference.as_ref()
    }
    /// <p>The pagination token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to retrieve.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl BatchListObjectParentPaths {
    /// Creates a new builder-style object to manufacture [`BatchListObjectParentPaths`](crate::types::BatchListObjectParentPaths).
    pub fn builder() -> crate::types::builders::BatchListObjectParentPathsBuilder {
        crate::types::builders::BatchListObjectParentPathsBuilder::default()
    }
}

/// A builder for [`BatchListObjectParentPaths`](crate::types::BatchListObjectParentPaths).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchListObjectParentPathsBuilder {
    pub(crate) object_reference: ::std::option::Option<crate::types::ObjectReference>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl BatchListObjectParentPathsBuilder {
    /// <p>The reference that identifies the object whose attributes will be listed.</p>
    /// This field is required.
    pub fn object_reference(mut self, input: crate::types::ObjectReference) -> Self {
        self.object_reference = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reference that identifies the object whose attributes will be listed.</p>
    pub fn set_object_reference(mut self, input: ::std::option::Option<crate::types::ObjectReference>) -> Self {
        self.object_reference = input;
        self
    }
    /// <p>The reference that identifies the object whose attributes will be listed.</p>
    pub fn get_object_reference(&self) -> &::std::option::Option<crate::types::ObjectReference> {
        &self.object_reference
    }
    /// <p>The pagination token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to retrieve.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to retrieve.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to retrieve.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`BatchListObjectParentPaths`](crate::types::BatchListObjectParentPaths).
    pub fn build(self) -> crate::types::BatchListObjectParentPaths {
        crate::types::BatchListObjectParentPaths {
            object_reference: self.object_reference,
            next_token: self.next_token,
            max_results: self.max_results,
        }
    }
}
