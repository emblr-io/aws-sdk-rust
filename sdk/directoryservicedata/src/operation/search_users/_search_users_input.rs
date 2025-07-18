// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct SearchUsersInput {
    /// <p>The identifier (ID) of the directory that's associated with the user.</p>
    pub directory_id: ::std::option::Option<::std::string::String>,
    /// <p>The domain name that's associated with the user.</p><note>
    /// <p>This parameter is optional, so you can return users outside of your Managed Microsoft AD domain. When no value is defined, only your Managed Microsoft AD users are returned.</p>
    /// <p>This value is case insensitive.</p>
    /// </note>
    pub realm: ::std::option::Option<::std::string::String>,
    /// <p>The attribute value that you want to search for.</p><note>
    /// <p>Wildcard <code>(*)</code> searches aren't supported. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    /// </note>
    pub search_string: ::std::option::Option<::std::string::String>,
    /// <p>One or more data attributes that are used to search for a user. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    pub search_attributes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An encoded paging token for paginated calls that can be passed back to retrieve the next page.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to be returned per request.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl SearchUsersInput {
    /// <p>The identifier (ID) of the directory that's associated with the user.</p>
    pub fn directory_id(&self) -> ::std::option::Option<&str> {
        self.directory_id.as_deref()
    }
    /// <p>The domain name that's associated with the user.</p><note>
    /// <p>This parameter is optional, so you can return users outside of your Managed Microsoft AD domain. When no value is defined, only your Managed Microsoft AD users are returned.</p>
    /// <p>This value is case insensitive.</p>
    /// </note>
    pub fn realm(&self) -> ::std::option::Option<&str> {
        self.realm.as_deref()
    }
    /// <p>The attribute value that you want to search for.</p><note>
    /// <p>Wildcard <code>(*)</code> searches aren't supported. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    /// </note>
    pub fn search_string(&self) -> ::std::option::Option<&str> {
        self.search_string.as_deref()
    }
    /// <p>One or more data attributes that are used to search for a user. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.search_attributes.is_none()`.
    pub fn search_attributes(&self) -> &[::std::string::String] {
        self.search_attributes.as_deref().unwrap_or_default()
    }
    /// <p>An encoded paging token for paginated calls that can be passed back to retrieve the next page.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ::std::fmt::Debug for SearchUsersInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SearchUsersInput");
        formatter.field("directory_id", &self.directory_id);
        formatter.field("realm", &self.realm);
        formatter.field("search_string", &"*** Sensitive Data Redacted ***");
        formatter.field("search_attributes", &self.search_attributes);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.field("max_results", &self.max_results);
        formatter.finish()
    }
}
impl SearchUsersInput {
    /// Creates a new builder-style object to manufacture [`SearchUsersInput`](crate::operation::search_users::SearchUsersInput).
    pub fn builder() -> crate::operation::search_users::builders::SearchUsersInputBuilder {
        crate::operation::search_users::builders::SearchUsersInputBuilder::default()
    }
}

/// A builder for [`SearchUsersInput`](crate::operation::search_users::SearchUsersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct SearchUsersInputBuilder {
    pub(crate) directory_id: ::std::option::Option<::std::string::String>,
    pub(crate) realm: ::std::option::Option<::std::string::String>,
    pub(crate) search_string: ::std::option::Option<::std::string::String>,
    pub(crate) search_attributes: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl SearchUsersInputBuilder {
    /// <p>The identifier (ID) of the directory that's associated with the user.</p>
    /// This field is required.
    pub fn directory_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier (ID) of the directory that's associated with the user.</p>
    pub fn set_directory_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_id = input;
        self
    }
    /// <p>The identifier (ID) of the directory that's associated with the user.</p>
    pub fn get_directory_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_id
    }
    /// <p>The domain name that's associated with the user.</p><note>
    /// <p>This parameter is optional, so you can return users outside of your Managed Microsoft AD domain. When no value is defined, only your Managed Microsoft AD users are returned.</p>
    /// <p>This value is case insensitive.</p>
    /// </note>
    pub fn realm(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.realm = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The domain name that's associated with the user.</p><note>
    /// <p>This parameter is optional, so you can return users outside of your Managed Microsoft AD domain. When no value is defined, only your Managed Microsoft AD users are returned.</p>
    /// <p>This value is case insensitive.</p>
    /// </note>
    pub fn set_realm(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.realm = input;
        self
    }
    /// <p>The domain name that's associated with the user.</p><note>
    /// <p>This parameter is optional, so you can return users outside of your Managed Microsoft AD domain. When no value is defined, only your Managed Microsoft AD users are returned.</p>
    /// <p>This value is case insensitive.</p>
    /// </note>
    pub fn get_realm(&self) -> &::std::option::Option<::std::string::String> {
        &self.realm
    }
    /// <p>The attribute value that you want to search for.</p><note>
    /// <p>Wildcard <code>(*)</code> searches aren't supported. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    /// </note>
    /// This field is required.
    pub fn search_string(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.search_string = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The attribute value that you want to search for.</p><note>
    /// <p>Wildcard <code>(*)</code> searches aren't supported. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    /// </note>
    pub fn set_search_string(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.search_string = input;
        self
    }
    /// <p>The attribute value that you want to search for.</p><note>
    /// <p>Wildcard <code>(*)</code> searches aren't supported. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    /// </note>
    pub fn get_search_string(&self) -> &::std::option::Option<::std::string::String> {
        &self.search_string
    }
    /// Appends an item to `search_attributes`.
    ///
    /// To override the contents of this collection use [`set_search_attributes`](Self::set_search_attributes).
    ///
    /// <p>One or more data attributes that are used to search for a user. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    pub fn search_attributes(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.search_attributes.unwrap_or_default();
        v.push(input.into());
        self.search_attributes = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more data attributes that are used to search for a user. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    pub fn set_search_attributes(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.search_attributes = input;
        self
    }
    /// <p>One or more data attributes that are used to search for a user. For a list of supported attributes, see <a href="https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ad_data_attributes.html">Directory Service Data Attributes</a>.</p>
    pub fn get_search_attributes(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.search_attributes
    }
    /// <p>An encoded paging token for paginated calls that can be passed back to retrieve the next page.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An encoded paging token for paginated calls that can be passed back to retrieve the next page.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>An encoded paging token for paginated calls that can be passed back to retrieve the next page.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to be returned per request.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`SearchUsersInput`](crate::operation::search_users::SearchUsersInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::search_users::SearchUsersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::search_users::SearchUsersInput {
            directory_id: self.directory_id,
            realm: self.realm,
            search_string: self.search_string,
            search_attributes: self.search_attributes,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
impl ::std::fmt::Debug for SearchUsersInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("SearchUsersInputBuilder");
        formatter.field("directory_id", &self.directory_id);
        formatter.field("realm", &self.realm);
        formatter.field("search_string", &"*** Sensitive Data Redacted ***");
        formatter.field("search_attributes", &self.search_attributes);
        formatter.field("next_token", &"*** Sensitive Data Redacted ***");
        formatter.field("max_results", &self.max_results);
        formatter.finish()
    }
}
