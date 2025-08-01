// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDataSetsInput {
    /// <p>The maximum number of results returned by a single call.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A property that defines the data set as OWNED by the account (for providers) or ENTITLED to the account (for subscribers).</p>
    pub origin: ::std::option::Option<::std::string::String>,
}
impl ListDataSetsInput {
    /// <p>The maximum number of results returned by a single call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A property that defines the data set as OWNED by the account (for providers) or ENTITLED to the account (for subscribers).</p>
    pub fn origin(&self) -> ::std::option::Option<&str> {
        self.origin.as_deref()
    }
}
impl ListDataSetsInput {
    /// Creates a new builder-style object to manufacture [`ListDataSetsInput`](crate::operation::list_data_sets::ListDataSetsInput).
    pub fn builder() -> crate::operation::list_data_sets::builders::ListDataSetsInputBuilder {
        crate::operation::list_data_sets::builders::ListDataSetsInputBuilder::default()
    }
}

/// A builder for [`ListDataSetsInput`](crate::operation::list_data_sets::ListDataSetsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDataSetsInputBuilder {
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) origin: ::std::option::Option<::std::string::String>,
}
impl ListDataSetsInputBuilder {
    /// <p>The maximum number of results returned by a single call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results returned by a single call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results returned by a single call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token value retrieved from a previous call to access the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>A property that defines the data set as OWNED by the account (for providers) or ENTITLED to the account (for subscribers).</p>
    pub fn origin(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.origin = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A property that defines the data set as OWNED by the account (for providers) or ENTITLED to the account (for subscribers).</p>
    pub fn set_origin(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.origin = input;
        self
    }
    /// <p>A property that defines the data set as OWNED by the account (for providers) or ENTITLED to the account (for subscribers).</p>
    pub fn get_origin(&self) -> &::std::option::Option<::std::string::String> {
        &self.origin
    }
    /// Consumes the builder and constructs a [`ListDataSetsInput`](crate::operation::list_data_sets::ListDataSetsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_data_sets::ListDataSetsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_data_sets::ListDataSetsInput {
            max_results: self.max_results,
            next_token: self.next_token,
            origin: self.origin,
        })
    }
}
