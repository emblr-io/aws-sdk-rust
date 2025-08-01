// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListMembersInput {
    /// <p>Specifies whether to list only currently associated members if <code>True</code> or to list all members within the organization if <code>False</code>.</p>
    pub only_associated: ::std::option::Option<bool>,
    /// <p>The maximum number of results the response can return. If your request would return more than the maximum the response will return a <code>nextToken</code> value, use this value when you call the action again to get the remaining results.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. If your response returns more than the <code>maxResults</code> maximum value it will also return a <code>nextToken</code> value. For subsequent calls, use the <code>nextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListMembersInput {
    /// <p>Specifies whether to list only currently associated members if <code>True</code> or to list all members within the organization if <code>False</code>.</p>
    pub fn only_associated(&self) -> ::std::option::Option<bool> {
        self.only_associated
    }
    /// <p>The maximum number of results the response can return. If your request would return more than the maximum the response will return a <code>nextToken</code> value, use this value when you call the action again to get the remaining results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. If your response returns more than the <code>maxResults</code> maximum value it will also return a <code>nextToken</code> value. For subsequent calls, use the <code>nextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListMembersInput {
    /// Creates a new builder-style object to manufacture [`ListMembersInput`](crate::operation::list_members::ListMembersInput).
    pub fn builder() -> crate::operation::list_members::builders::ListMembersInputBuilder {
        crate::operation::list_members::builders::ListMembersInputBuilder::default()
    }
}

/// A builder for [`ListMembersInput`](crate::operation::list_members::ListMembersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListMembersInputBuilder {
    pub(crate) only_associated: ::std::option::Option<bool>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListMembersInputBuilder {
    /// <p>Specifies whether to list only currently associated members if <code>True</code> or to list all members within the organization if <code>False</code>.</p>
    pub fn only_associated(mut self, input: bool) -> Self {
        self.only_associated = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether to list only currently associated members if <code>True</code> or to list all members within the organization if <code>False</code>.</p>
    pub fn set_only_associated(mut self, input: ::std::option::Option<bool>) -> Self {
        self.only_associated = input;
        self
    }
    /// <p>Specifies whether to list only currently associated members if <code>True</code> or to list all members within the organization if <code>False</code>.</p>
    pub fn get_only_associated(&self) -> &::std::option::Option<bool> {
        &self.only_associated
    }
    /// <p>The maximum number of results the response can return. If your request would return more than the maximum the response will return a <code>nextToken</code> value, use this value when you call the action again to get the remaining results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results the response can return. If your request would return more than the maximum the response will return a <code>nextToken</code> value, use this value when you call the action again to get the remaining results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results the response can return. If your request would return more than the maximum the response will return a <code>nextToken</code> value, use this value when you call the action again to get the remaining results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. If your response returns more than the <code>maxResults</code> maximum value it will also return a <code>nextToken</code> value. For subsequent calls, use the <code>nextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. If your response returns more than the <code>maxResults</code> maximum value it will also return a <code>nextToken</code> value. For subsequent calls, use the <code>nextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to use for paginating results that are returned in the response. Set the value of this parameter to null for the first request to a list action. If your response returns more than the <code>maxResults</code> maximum value it will also return a <code>nextToken</code> value. For subsequent calls, use the <code>nextToken</code> value returned from the previous request to continue listing results after the first page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListMembersInput`](crate::operation::list_members::ListMembersInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_members::ListMembersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_members::ListMembersInput {
            only_associated: self.only_associated,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
