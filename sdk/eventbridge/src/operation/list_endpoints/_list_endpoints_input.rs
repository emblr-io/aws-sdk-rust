// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEndpointsInput {
    /// <p>A value that will return a subset of the endpoints associated with this account. For example, <code>"NamePrefix": "ABC"</code> will return all endpoints with "ABC" in the name.</p>
    pub name_prefix: ::std::option::Option<::std::string::String>,
    /// <p>The primary Region of the endpoints associated with this account. For example <code>"HomeRegion": "us-east-1"</code>.</p>
    pub home_region: ::std::option::Option<::std::string::String>,
    /// <p>The token returned by a previous call, which you can use to retrieve the next set of results.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results returned by the call.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListEndpointsInput {
    /// <p>A value that will return a subset of the endpoints associated with this account. For example, <code>"NamePrefix": "ABC"</code> will return all endpoints with "ABC" in the name.</p>
    pub fn name_prefix(&self) -> ::std::option::Option<&str> {
        self.name_prefix.as_deref()
    }
    /// <p>The primary Region of the endpoints associated with this account. For example <code>"HomeRegion": "us-east-1"</code>.</p>
    pub fn home_region(&self) -> ::std::option::Option<&str> {
        self.home_region.as_deref()
    }
    /// <p>The token returned by a previous call, which you can use to retrieve the next set of results.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results returned by the call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListEndpointsInput {
    /// Creates a new builder-style object to manufacture [`ListEndpointsInput`](crate::operation::list_endpoints::ListEndpointsInput).
    pub fn builder() -> crate::operation::list_endpoints::builders::ListEndpointsInputBuilder {
        crate::operation::list_endpoints::builders::ListEndpointsInputBuilder::default()
    }
}

/// A builder for [`ListEndpointsInput`](crate::operation::list_endpoints::ListEndpointsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEndpointsInputBuilder {
    pub(crate) name_prefix: ::std::option::Option<::std::string::String>,
    pub(crate) home_region: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListEndpointsInputBuilder {
    /// <p>A value that will return a subset of the endpoints associated with this account. For example, <code>"NamePrefix": "ABC"</code> will return all endpoints with "ABC" in the name.</p>
    pub fn name_prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name_prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A value that will return a subset of the endpoints associated with this account. For example, <code>"NamePrefix": "ABC"</code> will return all endpoints with "ABC" in the name.</p>
    pub fn set_name_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name_prefix = input;
        self
    }
    /// <p>A value that will return a subset of the endpoints associated with this account. For example, <code>"NamePrefix": "ABC"</code> will return all endpoints with "ABC" in the name.</p>
    pub fn get_name_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.name_prefix
    }
    /// <p>The primary Region of the endpoints associated with this account. For example <code>"HomeRegion": "us-east-1"</code>.</p>
    pub fn home_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.home_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The primary Region of the endpoints associated with this account. For example <code>"HomeRegion": "us-east-1"</code>.</p>
    pub fn set_home_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.home_region = input;
        self
    }
    /// <p>The primary Region of the endpoints associated with this account. For example <code>"HomeRegion": "us-east-1"</code>.</p>
    pub fn get_home_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.home_region
    }
    /// <p>The token returned by a previous call, which you can use to retrieve the next set of results.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token returned by a previous call, which you can use to retrieve the next set of results.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token returned by a previous call, which you can use to retrieve the next set of results.</p>
    /// <p>The value of <code>nextToken</code> is a unique pagination token for each page. To retrieve the next page of results, make the call again using the returned token. Keep all other arguments unchanged.</p>
    /// <p>Using an expired pagination token results in an <code>HTTP 400 InvalidToken</code> error.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results returned by the call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results returned by the call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results returned by the call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListEndpointsInput`](crate::operation::list_endpoints::ListEndpointsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_endpoints::ListEndpointsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_endpoints::ListEndpointsInput {
            name_prefix: self.name_prefix,
            home_region: self.home_region,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
