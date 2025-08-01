// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SearchUsersInput {
    /// <p>The ID of an existing collection containing the UserID, used with a UserId or FaceId. If a FaceId is provided, UserId isn’t required to be present in the Collection.</p>
    pub collection_id: ::std::option::Option<::std::string::String>,
    /// <p>ID for the existing User.</p>
    pub user_id: ::std::option::Option<::std::string::String>,
    /// <p>ID for the existing face.</p>
    pub face_id: ::std::option::Option<::std::string::String>,
    /// <p>Optional value that specifies the minimum confidence in the matched UserID to return. Default value of 80.</p>
    pub user_match_threshold: ::std::option::Option<f32>,
    /// <p>Maximum number of identities to return.</p>
    pub max_users: ::std::option::Option<i32>,
}
impl SearchUsersInput {
    /// <p>The ID of an existing collection containing the UserID, used with a UserId or FaceId. If a FaceId is provided, UserId isn’t required to be present in the Collection.</p>
    pub fn collection_id(&self) -> ::std::option::Option<&str> {
        self.collection_id.as_deref()
    }
    /// <p>ID for the existing User.</p>
    pub fn user_id(&self) -> ::std::option::Option<&str> {
        self.user_id.as_deref()
    }
    /// <p>ID for the existing face.</p>
    pub fn face_id(&self) -> ::std::option::Option<&str> {
        self.face_id.as_deref()
    }
    /// <p>Optional value that specifies the minimum confidence in the matched UserID to return. Default value of 80.</p>
    pub fn user_match_threshold(&self) -> ::std::option::Option<f32> {
        self.user_match_threshold
    }
    /// <p>Maximum number of identities to return.</p>
    pub fn max_users(&self) -> ::std::option::Option<i32> {
        self.max_users
    }
}
impl SearchUsersInput {
    /// Creates a new builder-style object to manufacture [`SearchUsersInput`](crate::operation::search_users::SearchUsersInput).
    pub fn builder() -> crate::operation::search_users::builders::SearchUsersInputBuilder {
        crate::operation::search_users::builders::SearchUsersInputBuilder::default()
    }
}

/// A builder for [`SearchUsersInput`](crate::operation::search_users::SearchUsersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SearchUsersInputBuilder {
    pub(crate) collection_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_id: ::std::option::Option<::std::string::String>,
    pub(crate) face_id: ::std::option::Option<::std::string::String>,
    pub(crate) user_match_threshold: ::std::option::Option<f32>,
    pub(crate) max_users: ::std::option::Option<i32>,
}
impl SearchUsersInputBuilder {
    /// <p>The ID of an existing collection containing the UserID, used with a UserId or FaceId. If a FaceId is provided, UserId isn’t required to be present in the Collection.</p>
    /// This field is required.
    pub fn collection_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collection_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an existing collection containing the UserID, used with a UserId or FaceId. If a FaceId is provided, UserId isn’t required to be present in the Collection.</p>
    pub fn set_collection_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collection_id = input;
        self
    }
    /// <p>The ID of an existing collection containing the UserID, used with a UserId or FaceId. If a FaceId is provided, UserId isn’t required to be present in the Collection.</p>
    pub fn get_collection_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.collection_id
    }
    /// <p>ID for the existing User.</p>
    pub fn user_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID for the existing User.</p>
    pub fn set_user_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_id = input;
        self
    }
    /// <p>ID for the existing User.</p>
    pub fn get_user_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_id
    }
    /// <p>ID for the existing face.</p>
    pub fn face_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.face_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ID for the existing face.</p>
    pub fn set_face_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.face_id = input;
        self
    }
    /// <p>ID for the existing face.</p>
    pub fn get_face_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.face_id
    }
    /// <p>Optional value that specifies the minimum confidence in the matched UserID to return. Default value of 80.</p>
    pub fn user_match_threshold(mut self, input: f32) -> Self {
        self.user_match_threshold = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional value that specifies the minimum confidence in the matched UserID to return. Default value of 80.</p>
    pub fn set_user_match_threshold(mut self, input: ::std::option::Option<f32>) -> Self {
        self.user_match_threshold = input;
        self
    }
    /// <p>Optional value that specifies the minimum confidence in the matched UserID to return. Default value of 80.</p>
    pub fn get_user_match_threshold(&self) -> &::std::option::Option<f32> {
        &self.user_match_threshold
    }
    /// <p>Maximum number of identities to return.</p>
    pub fn max_users(mut self, input: i32) -> Self {
        self.max_users = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of identities to return.</p>
    pub fn set_max_users(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_users = input;
        self
    }
    /// <p>Maximum number of identities to return.</p>
    pub fn get_max_users(&self) -> &::std::option::Option<i32> {
        &self.max_users
    }
    /// Consumes the builder and constructs a [`SearchUsersInput`](crate::operation::search_users::SearchUsersInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::search_users::SearchUsersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::search_users::SearchUsersInput {
            collection_id: self.collection_id,
            user_id: self.user_id,
            face_id: self.face_id,
            user_match_threshold: self.user_match_threshold,
            max_users: self.max_users,
        })
    }
}
