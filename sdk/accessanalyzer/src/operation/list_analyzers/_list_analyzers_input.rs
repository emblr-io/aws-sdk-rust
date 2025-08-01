// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Retrieves a list of analyzers.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAnalyzersInput {
    /// <p>A token used for pagination of results returned.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The type of analyzer.</p>
    pub r#type: ::std::option::Option<crate::types::Type>,
}
impl ListAnalyzersInput {
    /// <p>A token used for pagination of results returned.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The type of analyzer.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::Type> {
        self.r#type.as_ref()
    }
}
impl ListAnalyzersInput {
    /// Creates a new builder-style object to manufacture [`ListAnalyzersInput`](crate::operation::list_analyzers::ListAnalyzersInput).
    pub fn builder() -> crate::operation::list_analyzers::builders::ListAnalyzersInputBuilder {
        crate::operation::list_analyzers::builders::ListAnalyzersInputBuilder::default()
    }
}

/// A builder for [`ListAnalyzersInput`](crate::operation::list_analyzers::ListAnalyzersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAnalyzersInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) r#type: ::std::option::Option<crate::types::Type>,
}
impl ListAnalyzersInputBuilder {
    /// <p>A token used for pagination of results returned.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token used for pagination of results returned.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token used for pagination of results returned.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The type of analyzer.</p>
    pub fn r#type(mut self, input: crate::types::Type) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of analyzer.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::Type>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of analyzer.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::Type> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`ListAnalyzersInput`](crate::operation::list_analyzers::ListAnalyzersInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_analyzers::ListAnalyzersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_analyzers::ListAnalyzersInput {
            next_token: self.next_token,
            max_results: self.max_results,
            r#type: self.r#type,
        })
    }
}
