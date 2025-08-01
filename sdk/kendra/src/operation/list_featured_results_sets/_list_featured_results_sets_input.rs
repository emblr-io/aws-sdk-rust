// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListFeaturedResultsSetsInput {
    /// <p>The identifier of the index used for featuring results.</p>
    pub index_id: ::std::option::Option<::std::string::String>,
    /// <p>If the response is truncated, Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of featured results sets.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of featured results sets to return.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListFeaturedResultsSetsInput {
    /// <p>The identifier of the index used for featuring results.</p>
    pub fn index_id(&self) -> ::std::option::Option<&str> {
        self.index_id.as_deref()
    }
    /// <p>If the response is truncated, Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of featured results sets.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of featured results sets to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListFeaturedResultsSetsInput {
    /// Creates a new builder-style object to manufacture [`ListFeaturedResultsSetsInput`](crate::operation::list_featured_results_sets::ListFeaturedResultsSetsInput).
    pub fn builder() -> crate::operation::list_featured_results_sets::builders::ListFeaturedResultsSetsInputBuilder {
        crate::operation::list_featured_results_sets::builders::ListFeaturedResultsSetsInputBuilder::default()
    }
}

/// A builder for [`ListFeaturedResultsSetsInput`](crate::operation::list_featured_results_sets::ListFeaturedResultsSetsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListFeaturedResultsSetsInputBuilder {
    pub(crate) index_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListFeaturedResultsSetsInputBuilder {
    /// <p>The identifier of the index used for featuring results.</p>
    /// This field is required.
    pub fn index_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.index_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the index used for featuring results.</p>
    pub fn set_index_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.index_id = input;
        self
    }
    /// <p>The identifier of the index used for featuring results.</p>
    pub fn get_index_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.index_id
    }
    /// <p>If the response is truncated, Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of featured results sets.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the response is truncated, Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of featured results sets.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the response is truncated, Amazon Kendra returns a pagination token in the response. You can use this pagination token to retrieve the next set of featured results sets.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of featured results sets to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of featured results sets to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of featured results sets to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListFeaturedResultsSetsInput`](crate::operation::list_featured_results_sets::ListFeaturedResultsSetsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_featured_results_sets::ListFeaturedResultsSetsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_featured_results_sets::ListFeaturedResultsSetsInput {
            index_id: self.index_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
