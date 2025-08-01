// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListUsersInput {
    /// <p>The globally unique identifier for the identity store, such as <code>d-1234567890</code>. In this example, <code>d-</code> is a fixed prefix, and <code>1234567890</code> is a randomly generated string that contains numbers and lower case letters. This value is generated at the time that a new identity store is created.</p>
    pub identity_store_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to be returned per request. This parameter is used in the <code>ListUsers</code> and <code>ListGroups</code> requests to specify how many results to return in one page. The length limit is 50 characters.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The pagination token used for the <code>ListUsers</code> and <code>ListGroups</code> API operations. This value is generated by the identity store service. It is returned in the API response if the total results are more than the size of one page. This token is also returned when it is used in the API request to search for the next page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of <code>Filter</code> objects, which is used in the <code>ListUsers</code> and <code>ListGroups</code> requests.</p>
    #[deprecated(note = "Using filters with ListUsers API is deprecated, please use GetGroupId API instead.")]
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
}
impl ListUsersInput {
    /// <p>The globally unique identifier for the identity store, such as <code>d-1234567890</code>. In this example, <code>d-</code> is a fixed prefix, and <code>1234567890</code> is a randomly generated string that contains numbers and lower case letters. This value is generated at the time that a new identity store is created.</p>
    pub fn identity_store_id(&self) -> ::std::option::Option<&str> {
        self.identity_store_id.as_deref()
    }
    /// <p>The maximum number of results to be returned per request. This parameter is used in the <code>ListUsers</code> and <code>ListGroups</code> requests to specify how many results to return in one page. The length limit is 50 characters.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The pagination token used for the <code>ListUsers</code> and <code>ListGroups</code> API operations. This value is generated by the identity store service. It is returned in the API response if the total results are more than the size of one page. This token is also returned when it is used in the API request to search for the next page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of <code>Filter</code> objects, which is used in the <code>ListUsers</code> and <code>ListGroups</code> requests.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    #[deprecated(note = "Using filters with ListUsers API is deprecated, please use GetGroupId API instead.")]
    pub fn filters(&self) -> &[crate::types::Filter] {
        self.filters.as_deref().unwrap_or_default()
    }
}
impl ListUsersInput {
    /// Creates a new builder-style object to manufacture [`ListUsersInput`](crate::operation::list_users::ListUsersInput).
    pub fn builder() -> crate::operation::list_users::builders::ListUsersInputBuilder {
        crate::operation::list_users::builders::ListUsersInputBuilder::default()
    }
}

/// A builder for [`ListUsersInput`](crate::operation::list_users::ListUsersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListUsersInputBuilder {
    pub(crate) identity_store_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>,
}
impl ListUsersInputBuilder {
    /// <p>The globally unique identifier for the identity store, such as <code>d-1234567890</code>. In this example, <code>d-</code> is a fixed prefix, and <code>1234567890</code> is a randomly generated string that contains numbers and lower case letters. This value is generated at the time that a new identity store is created.</p>
    /// This field is required.
    pub fn identity_store_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.identity_store_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The globally unique identifier for the identity store, such as <code>d-1234567890</code>. In this example, <code>d-</code> is a fixed prefix, and <code>1234567890</code> is a randomly generated string that contains numbers and lower case letters. This value is generated at the time that a new identity store is created.</p>
    pub fn set_identity_store_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.identity_store_id = input;
        self
    }
    /// <p>The globally unique identifier for the identity store, such as <code>d-1234567890</code>. In this example, <code>d-</code> is a fixed prefix, and <code>1234567890</code> is a randomly generated string that contains numbers and lower case letters. This value is generated at the time that a new identity store is created.</p>
    pub fn get_identity_store_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.identity_store_id
    }
    /// <p>The maximum number of results to be returned per request. This parameter is used in the <code>ListUsers</code> and <code>ListGroups</code> requests to specify how many results to return in one page. The length limit is 50 characters.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to be returned per request. This parameter is used in the <code>ListUsers</code> and <code>ListGroups</code> requests to specify how many results to return in one page. The length limit is 50 characters.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to be returned per request. This parameter is used in the <code>ListUsers</code> and <code>ListGroups</code> requests to specify how many results to return in one page. The length limit is 50 characters.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The pagination token used for the <code>ListUsers</code> and <code>ListGroups</code> API operations. This value is generated by the identity store service. It is returned in the API response if the total results are more than the size of one page. This token is also returned when it is used in the API request to search for the next page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token used for the <code>ListUsers</code> and <code>ListGroups</code> API operations. This value is generated by the identity store service. It is returned in the API response if the total results are more than the size of one page. This token is also returned when it is used in the API request to search for the next page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token used for the <code>ListUsers</code> and <code>ListGroups</code> API operations. This value is generated by the identity store service. It is returned in the API response if the total results are more than the size of one page. This token is also returned when it is used in the API request to search for the next page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>A list of <code>Filter</code> objects, which is used in the <code>ListUsers</code> and <code>ListGroups</code> requests.</p>
    #[deprecated(note = "Using filters with ListUsers API is deprecated, please use GetGroupId API instead.")]
    pub fn filters(mut self, input: crate::types::Filter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of <code>Filter</code> objects, which is used in the <code>ListUsers</code> and <code>ListGroups</code> requests.</p>
    #[deprecated(note = "Using filters with ListUsers API is deprecated, please use GetGroupId API instead.")]
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Filter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>A list of <code>Filter</code> objects, which is used in the <code>ListUsers</code> and <code>ListGroups</code> requests.</p>
    #[deprecated(note = "Using filters with ListUsers API is deprecated, please use GetGroupId API instead.")]
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Filter>> {
        &self.filters
    }
    /// Consumes the builder and constructs a [`ListUsersInput`](crate::operation::list_users::ListUsersInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::list_users::ListUsersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_users::ListUsersInput {
            identity_store_id: self.identity_store_id,
            max_results: self.max_results,
            next_token: self.next_token,
            filters: self.filters,
        })
    }
}
