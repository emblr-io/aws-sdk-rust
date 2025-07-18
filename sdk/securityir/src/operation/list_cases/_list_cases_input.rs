// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListCasesInput {
    /// <p>Optional element.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>Optional element for ListCases to limit the number of responses.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListCasesInput {
    /// <p>Optional element.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>Optional element for ListCases to limit the number of responses.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListCasesInput {
    /// Creates a new builder-style object to manufacture [`ListCasesInput`](crate::operation::list_cases::ListCasesInput).
    pub fn builder() -> crate::operation::list_cases::builders::ListCasesInputBuilder {
        crate::operation::list_cases::builders::ListCasesInputBuilder::default()
    }
}

/// A builder for [`ListCasesInput`](crate::operation::list_cases::ListCasesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListCasesInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListCasesInputBuilder {
    /// <p>Optional element.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Optional element.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>Optional element.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>Optional element for ListCases to limit the number of responses.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional element for ListCases to limit the number of responses.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>Optional element for ListCases to limit the number of responses.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListCasesInput`](crate::operation::list_cases::ListCasesInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_cases::ListCasesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_cases::ListCasesInput {
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
