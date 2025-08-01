// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListLayoutsInput {
    /// <p>The unique identifier of the Cases domain.</p>
    pub domain_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return per page.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListLayoutsInput {
    /// <p>The unique identifier of the Cases domain.</p>
    pub fn domain_id(&self) -> ::std::option::Option<&str> {
        self.domain_id.as_deref()
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListLayoutsInput {
    /// Creates a new builder-style object to manufacture [`ListLayoutsInput`](crate::operation::list_layouts::ListLayoutsInput).
    pub fn builder() -> crate::operation::list_layouts::builders::ListLayoutsInputBuilder {
        crate::operation::list_layouts::builders::ListLayoutsInputBuilder::default()
    }
}

/// A builder for [`ListLayoutsInput`](crate::operation::list_layouts::ListLayoutsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListLayoutsInputBuilder {
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListLayoutsInputBuilder {
    /// <p>The unique identifier of the Cases domain.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Cases domain.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The unique identifier of the Cases domain.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListLayoutsInput`](crate::operation::list_layouts::ListLayoutsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_layouts::ListLayoutsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_layouts::ListLayoutsInput {
            domain_id: self.domain_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
