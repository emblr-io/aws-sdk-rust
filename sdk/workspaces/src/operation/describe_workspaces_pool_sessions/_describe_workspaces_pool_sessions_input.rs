// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeWorkspacesPoolSessionsInput {
    /// <p>The identifier of the pool.</p>
    pub pool_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the user.</p>
    pub user_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeWorkspacesPoolSessionsInput {
    /// <p>The identifier of the pool.</p>
    pub fn pool_id(&self) -> ::std::option::Option<&str> {
        self.pool_id.as_deref()
    }
    /// <p>The identifier of the user.</p>
    pub fn user_id(&self) -> ::std::option::Option<&str> {
        self.user_id.as_deref()
    }
    /// <p>The maximum size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeWorkspacesPoolSessionsInput {
    /// Creates a new builder-style object to manufacture [`DescribeWorkspacesPoolSessionsInput`](crate::operation::describe_workspaces_pool_sessions::DescribeWorkspacesPoolSessionsInput).
    pub fn builder() -> crate::operation::describe_workspaces_pool_sessions::builders::DescribeWorkspacesPoolSessionsInputBuilder {
        crate::operation::describe_workspaces_pool_sessions::builders::DescribeWorkspacesPoolSessionsInputBuilder::default()
    }
}

/// A builder for [`DescribeWorkspacesPoolSessionsInput`](crate::operation::describe_workspaces_pool_sessions::DescribeWorkspacesPoolSessionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeWorkspacesPoolSessionsInputBuilder {
    pub(crate) pool_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_id: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeWorkspacesPoolSessionsInputBuilder {
    /// <p>The identifier of the pool.</p>
    /// This field is required.
    pub fn pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the pool.</p>
    pub fn set_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pool_id = input;
        self
    }
    /// <p>The identifier of the pool.</p>
    pub fn get_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pool_id
    }
    /// <p>The identifier of the user.</p>
    pub fn user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the user.</p>
    pub fn set_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_id = input;
        self
    }
    /// <p>The identifier of the user.</p>
    pub fn get_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_id
    }
    /// <p>The maximum size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum size of each page of results. The default value is 20 and the maximum value is 50.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// <p>If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If you received a <code>NextToken</code> from a previous call that was paginated, provide this token to receive the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeWorkspacesPoolSessionsInput`](crate::operation::describe_workspaces_pool_sessions::DescribeWorkspacesPoolSessionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_workspaces_pool_sessions::DescribeWorkspacesPoolSessionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_workspaces_pool_sessions::DescribeWorkspacesPoolSessionsInput {
            pool_id: self.pool_id,
            user_id: self.user_id,
            limit: self.limit,
            next_token: self.next_token,
        })
    }
}
