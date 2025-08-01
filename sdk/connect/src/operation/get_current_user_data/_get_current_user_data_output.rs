// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCurrentUserDataOutput {
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of the user data that is returned.</p>
    pub user_data_list: ::std::option::Option<::std::vec::Vec<crate::types::UserData>>,
    /// <p>The total count of the result, regardless of the current page size.</p>
    pub approximate_total_count: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl GetCurrentUserDataOutput {
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of the user data that is returned.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.user_data_list.is_none()`.
    pub fn user_data_list(&self) -> &[crate::types::UserData] {
        self.user_data_list.as_deref().unwrap_or_default()
    }
    /// <p>The total count of the result, regardless of the current page size.</p>
    pub fn approximate_total_count(&self) -> ::std::option::Option<i64> {
        self.approximate_total_count
    }
}
impl ::aws_types::request_id::RequestId for GetCurrentUserDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetCurrentUserDataOutput {
    /// Creates a new builder-style object to manufacture [`GetCurrentUserDataOutput`](crate::operation::get_current_user_data::GetCurrentUserDataOutput).
    pub fn builder() -> crate::operation::get_current_user_data::builders::GetCurrentUserDataOutputBuilder {
        crate::operation::get_current_user_data::builders::GetCurrentUserDataOutputBuilder::default()
    }
}

/// A builder for [`GetCurrentUserDataOutput`](crate::operation::get_current_user_data::GetCurrentUserDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCurrentUserDataOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) user_data_list: ::std::option::Option<::std::vec::Vec<crate::types::UserData>>,
    pub(crate) approximate_total_count: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl GetCurrentUserDataOutputBuilder {
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If there are additional results, this is the token for the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `user_data_list`.
    ///
    /// To override the contents of this collection use [`set_user_data_list`](Self::set_user_data_list).
    ///
    /// <p>A list of the user data that is returned.</p>
    pub fn user_data_list(mut self, input: crate::types::UserData) -> Self {
        let mut v = self.user_data_list.unwrap_or_default();
        v.push(input);
        self.user_data_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the user data that is returned.</p>
    pub fn set_user_data_list(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UserData>>) -> Self {
        self.user_data_list = input;
        self
    }
    /// <p>A list of the user data that is returned.</p>
    pub fn get_user_data_list(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UserData>> {
        &self.user_data_list
    }
    /// <p>The total count of the result, regardless of the current page size.</p>
    pub fn approximate_total_count(mut self, input: i64) -> Self {
        self.approximate_total_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total count of the result, regardless of the current page size.</p>
    pub fn set_approximate_total_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.approximate_total_count = input;
        self
    }
    /// <p>The total count of the result, regardless of the current page size.</p>
    pub fn get_approximate_total_count(&self) -> &::std::option::Option<i64> {
        &self.approximate_total_count
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetCurrentUserDataOutput`](crate::operation::get_current_user_data::GetCurrentUserDataOutput).
    pub fn build(self) -> crate::operation::get_current_user_data::GetCurrentUserDataOutput {
        crate::operation::get_current_user_data::GetCurrentUserDataOutput {
            next_token: self.next_token,
            user_data_list: self.user_data_list,
            approximate_total_count: self.approximate_total_count,
            _request_id: self._request_id,
        }
    }
}
