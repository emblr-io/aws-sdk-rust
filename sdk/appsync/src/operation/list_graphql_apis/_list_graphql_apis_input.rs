// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListGraphqlApisInput {
    /// <p>An identifier that was returned from the previous call to this operation, which you can use to return the next set of items in the list.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results that you want the request to return.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The value that indicates whether the GraphQL API is a standard API (<code>GRAPHQL</code>) or merged API (<code>MERGED</code>).</p>
    pub api_type: ::std::option::Option<crate::types::GraphQlApiType>,
    /// <p>The account owner of the GraphQL API.</p>
    pub owner: ::std::option::Option<crate::types::Ownership>,
}
impl ListGraphqlApisInput {
    /// <p>An identifier that was returned from the previous call to this operation, which you can use to return the next set of items in the list.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results that you want the request to return.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The value that indicates whether the GraphQL API is a standard API (<code>GRAPHQL</code>) or merged API (<code>MERGED</code>).</p>
    pub fn api_type(&self) -> ::std::option::Option<&crate::types::GraphQlApiType> {
        self.api_type.as_ref()
    }
    /// <p>The account owner of the GraphQL API.</p>
    pub fn owner(&self) -> ::std::option::Option<&crate::types::Ownership> {
        self.owner.as_ref()
    }
}
impl ListGraphqlApisInput {
    /// Creates a new builder-style object to manufacture [`ListGraphqlApisInput`](crate::operation::list_graphql_apis::ListGraphqlApisInput).
    pub fn builder() -> crate::operation::list_graphql_apis::builders::ListGraphqlApisInputBuilder {
        crate::operation::list_graphql_apis::builders::ListGraphqlApisInputBuilder::default()
    }
}

/// A builder for [`ListGraphqlApisInput`](crate::operation::list_graphql_apis::ListGraphqlApisInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListGraphqlApisInputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) api_type: ::std::option::Option<crate::types::GraphQlApiType>,
    pub(crate) owner: ::std::option::Option<crate::types::Ownership>,
}
impl ListGraphqlApisInputBuilder {
    /// <p>An identifier that was returned from the previous call to this operation, which you can use to return the next set of items in the list.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An identifier that was returned from the previous call to this operation, which you can use to return the next set of items in the list.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An identifier that was returned from the previous call to this operation, which you can use to return the next set of items in the list.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results that you want the request to return.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results that you want the request to return.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results that you want the request to return.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The value that indicates whether the GraphQL API is a standard API (<code>GRAPHQL</code>) or merged API (<code>MERGED</code>).</p>
    pub fn api_type(mut self, input: crate::types::GraphQlApiType) -> Self {
        self.api_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value that indicates whether the GraphQL API is a standard API (<code>GRAPHQL</code>) or merged API (<code>MERGED</code>).</p>
    pub fn set_api_type(mut self, input: ::std::option::Option<crate::types::GraphQlApiType>) -> Self {
        self.api_type = input;
        self
    }
    /// <p>The value that indicates whether the GraphQL API is a standard API (<code>GRAPHQL</code>) or merged API (<code>MERGED</code>).</p>
    pub fn get_api_type(&self) -> &::std::option::Option<crate::types::GraphQlApiType> {
        &self.api_type
    }
    /// <p>The account owner of the GraphQL API.</p>
    pub fn owner(mut self, input: crate::types::Ownership) -> Self {
        self.owner = ::std::option::Option::Some(input);
        self
    }
    /// <p>The account owner of the GraphQL API.</p>
    pub fn set_owner(mut self, input: ::std::option::Option<crate::types::Ownership>) -> Self {
        self.owner = input;
        self
    }
    /// <p>The account owner of the GraphQL API.</p>
    pub fn get_owner(&self) -> &::std::option::Option<crate::types::Ownership> {
        &self.owner
    }
    /// Consumes the builder and constructs a [`ListGraphqlApisInput`](crate::operation::list_graphql_apis::ListGraphqlApisInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_graphql_apis::ListGraphqlApisInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_graphql_apis::ListGraphqlApisInput {
            next_token: self.next_token,
            max_results: self.max_results,
            api_type: self.api_type,
            owner: self.owner,
        })
    }
}
