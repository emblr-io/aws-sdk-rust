// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetListsMetadataInput {
    /// <p>The name of the list.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The next token for the subsequent request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of objects to return for the request.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetListsMetadataInput {
    /// <p>The name of the list.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The next token for the subsequent request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of objects to return for the request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetListsMetadataInput {
    /// Creates a new builder-style object to manufacture [`GetListsMetadataInput`](crate::operation::get_lists_metadata::GetListsMetadataInput).
    pub fn builder() -> crate::operation::get_lists_metadata::builders::GetListsMetadataInputBuilder {
        crate::operation::get_lists_metadata::builders::GetListsMetadataInputBuilder::default()
    }
}

/// A builder for [`GetListsMetadataInput`](crate::operation::get_lists_metadata::GetListsMetadataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetListsMetadataInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetListsMetadataInputBuilder {
    /// <p>The name of the list.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the list.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the list.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The next token for the subsequent request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next token for the subsequent request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next token for the subsequent request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of objects to return for the request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of objects to return for the request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of objects to return for the request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetListsMetadataInput`](crate::operation::get_lists_metadata::GetListsMetadataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_lists_metadata::GetListsMetadataInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_lists_metadata::GetListsMetadataInput {
            name: self.name,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
