// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetVariablesInput {
    /// <p>The name of the variable.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The next page token of the get variable request.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The max size per page determined for the get variable request.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl GetVariablesInput {
    /// <p>The name of the variable.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The next page token of the get variable request.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The max size per page determined for the get variable request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl GetVariablesInput {
    /// Creates a new builder-style object to manufacture [`GetVariablesInput`](crate::operation::get_variables::GetVariablesInput).
    pub fn builder() -> crate::operation::get_variables::builders::GetVariablesInputBuilder {
        crate::operation::get_variables::builders::GetVariablesInputBuilder::default()
    }
}

/// A builder for [`GetVariablesInput`](crate::operation::get_variables::GetVariablesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetVariablesInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl GetVariablesInputBuilder {
    /// <p>The name of the variable.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the variable.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the variable.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The next page token of the get variable request.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The next page token of the get variable request.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The next page token of the get variable request.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The max size per page determined for the get variable request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The max size per page determined for the get variable request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The max size per page determined for the get variable request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`GetVariablesInput`](crate::operation::get_variables::GetVariablesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_variables::GetVariablesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_variables::GetVariablesInput {
            name: self.name,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
