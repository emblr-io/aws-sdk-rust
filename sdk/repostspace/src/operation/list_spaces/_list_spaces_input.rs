// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListSpacesInput {
    /// <p>The token for the next set of private re:Posts to return. You receive this token from a previous ListSpaces operation.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of private re:Posts to include in the results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListSpacesInput {
    /// <p>The token for the next set of private re:Posts to return. You receive this token from a previous ListSpaces operation.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of private re:Posts to include in the results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListSpacesInput {
    /// Creates a new builder-style object to manufacture [`ListSpacesInput`](crate::operation::list_spaces::ListSpacesInput).
    pub fn builder() -> crate::operation::list_spaces::builders::ListSpacesInputBuilder {
        crate::operation::list_spaces::builders::ListSpacesInputBuilder::default()
    }
}

/// A builder for [`ListSpacesInput`](crate::operation::list_spaces::ListSpacesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListSpacesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListSpacesInputBuilder {
    /// <p>The token for the next set of private re:Posts to return. You receive this token from a previous ListSpaces operation.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of private re:Posts to return. You receive this token from a previous ListSpaces operation.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of private re:Posts to return. You receive this token from a previous ListSpaces operation.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of private re:Posts to include in the results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of private re:Posts to include in the results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of private re:Posts to include in the results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListSpacesInput`](crate::operation::list_spaces::ListSpacesInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_spaces::ListSpacesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_spaces::ListSpacesInput {
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
