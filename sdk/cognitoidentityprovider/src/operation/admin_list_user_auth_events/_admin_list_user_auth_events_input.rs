// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AdminListUserAuthEventsInput {
    /// <p>The Id of the user pool that contains the user profile with the logged events.</p>
    pub user_pool_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    pub username: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of authentication events to return. Returns 60 events if you set <code>MaxResults</code> to 0, or if you don't include a <code>MaxResults</code> parameter.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>This API operation returns a limited number of results. The pagination token is an identifier that you can present in an additional API request with the same parameters. When you include the pagination token, Amazon Cognito returns the next set of items after the current list. Subsequent requests return a new pagination token. By use of this token, you can paginate through the full list of items.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl AdminListUserAuthEventsInput {
    /// <p>The Id of the user pool that contains the user profile with the logged events.</p>
    pub fn user_pool_id(&self) -> ::std::option::Option<&str> {
        self.user_pool_id.as_deref()
    }
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
    /// <p>The maximum number of authentication events to return. Returns 60 events if you set <code>MaxResults</code> to 0, or if you don't include a <code>MaxResults</code> parameter.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>This API operation returns a limited number of results. The pagination token is an identifier that you can present in an additional API request with the same parameters. When you include the pagination token, Amazon Cognito returns the next set of items after the current list. Subsequent requests return a new pagination token. By use of this token, you can paginate through the full list of items.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::std::fmt::Debug for AdminListUserAuthEventsInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AdminListUserAuthEventsInput");
        formatter.field("user_pool_id", &self.user_pool_id);
        formatter.field("username", &"*** Sensitive Data Redacted ***");
        formatter.field("max_results", &self.max_results);
        formatter.field("next_token", &self.next_token);
        formatter.finish()
    }
}
impl AdminListUserAuthEventsInput {
    /// Creates a new builder-style object to manufacture [`AdminListUserAuthEventsInput`](crate::operation::admin_list_user_auth_events::AdminListUserAuthEventsInput).
    pub fn builder() -> crate::operation::admin_list_user_auth_events::builders::AdminListUserAuthEventsInputBuilder {
        crate::operation::admin_list_user_auth_events::builders::AdminListUserAuthEventsInputBuilder::default()
    }
}

/// A builder for [`AdminListUserAuthEventsInput`](crate::operation::admin_list_user_auth_events::AdminListUserAuthEventsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AdminListUserAuthEventsInputBuilder {
    pub(crate) user_pool_id: ::std::option::Option<::std::string::String>,
    pub(crate) username: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl AdminListUserAuthEventsInputBuilder {
    /// <p>The Id of the user pool that contains the user profile with the logged events.</p>
    /// This field is required.
    pub fn user_pool_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_pool_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Id of the user pool that contains the user profile with the logged events.</p>
    pub fn set_user_pool_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_pool_id = input;
        self
    }
    /// <p>The Id of the user pool that contains the user profile with the logged events.</p>
    pub fn get_user_pool_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_pool_id
    }
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    /// This field is required.
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>The name of the user that you want to query or modify. The value of this parameter is typically your user's username, but it can be any of their alias attributes. If <code>username</code> isn't an alias attribute in your user pool, this value must be the <code>sub</code> of a local user or the username of a user from a third-party IdP.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// <p>The maximum number of authentication events to return. Returns 60 events if you set <code>MaxResults</code> to 0, or if you don't include a <code>MaxResults</code> parameter.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of authentication events to return. Returns 60 events if you set <code>MaxResults</code> to 0, or if you don't include a <code>MaxResults</code> parameter.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of authentication events to return. Returns 60 events if you set <code>MaxResults</code> to 0, or if you don't include a <code>MaxResults</code> parameter.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>This API operation returns a limited number of results. The pagination token is an identifier that you can present in an additional API request with the same parameters. When you include the pagination token, Amazon Cognito returns the next set of items after the current list. Subsequent requests return a new pagination token. By use of this token, you can paginate through the full list of items.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This API operation returns a limited number of results. The pagination token is an identifier that you can present in an additional API request with the same parameters. When you include the pagination token, Amazon Cognito returns the next set of items after the current list. Subsequent requests return a new pagination token. By use of this token, you can paginate through the full list of items.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>This API operation returns a limited number of results. The pagination token is an identifier that you can present in an additional API request with the same parameters. When you include the pagination token, Amazon Cognito returns the next set of items after the current list. Subsequent requests return a new pagination token. By use of this token, you can paginate through the full list of items.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`AdminListUserAuthEventsInput`](crate::operation::admin_list_user_auth_events::AdminListUserAuthEventsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::admin_list_user_auth_events::AdminListUserAuthEventsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::admin_list_user_auth_events::AdminListUserAuthEventsInput {
            user_pool_id: self.user_pool_id,
            username: self.username,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
impl ::std::fmt::Debug for AdminListUserAuthEventsInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AdminListUserAuthEventsInputBuilder");
        formatter.field("user_pool_id", &self.user_pool_id);
        formatter.field("username", &"*** Sensitive Data Redacted ***");
        formatter.field("max_results", &self.max_results);
        formatter.field("next_token", &self.next_token);
        formatter.finish()
    }
}
