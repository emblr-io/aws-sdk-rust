// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLibraryItemOutput {
    /// <p>The unique identifier of the updated library item.</p>
    pub library_item_id: ::std::string::String,
    /// <p>The unique identifier of the Q App associated with the library item.</p>
    pub app_id: ::std::string::String,
    /// <p>The version of the Q App associated with the library item.</p>
    pub app_version: i32,
    /// <p>The categories associated with the updated library item.</p>
    pub categories: ::std::vec::Vec<crate::types::Category>,
    /// <p>The new status of the updated library item.</p>
    pub status: ::std::string::String,
    /// <p>The date and time the library item was originally created.</p>
    pub created_at: ::aws_smithy_types::DateTime,
    /// <p>The user who originally created the library item.</p>
    pub created_by: ::std::string::String,
    /// <p>The date and time the library item was last updated.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The user who last updated the library item.</p>
    pub updated_by: ::std::option::Option<::std::string::String>,
    /// <p>The number of ratings the library item has received.</p>
    pub rating_count: i32,
    /// <p>Whether the current user has rated the library item.</p>
    pub is_rated_by_user: ::std::option::Option<bool>,
    /// <p>The number of users who have the associated Q App.</p>
    pub user_count: ::std::option::Option<i32>,
    /// <p>Indicates whether the library item has been verified.</p>
    pub is_verified: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl UpdateLibraryItemOutput {
    /// <p>The unique identifier of the updated library item.</p>
    pub fn library_item_id(&self) -> &str {
        use std::ops::Deref;
        self.library_item_id.deref()
    }
    /// <p>The unique identifier of the Q App associated with the library item.</p>
    pub fn app_id(&self) -> &str {
        use std::ops::Deref;
        self.app_id.deref()
    }
    /// <p>The version of the Q App associated with the library item.</p>
    pub fn app_version(&self) -> i32 {
        self.app_version
    }
    /// <p>The categories associated with the updated library item.</p>
    pub fn categories(&self) -> &[crate::types::Category] {
        use std::ops::Deref;
        self.categories.deref()
    }
    /// <p>The new status of the updated library item.</p>
    pub fn status(&self) -> &str {
        use std::ops::Deref;
        self.status.deref()
    }
    /// <p>The date and time the library item was originally created.</p>
    pub fn created_at(&self) -> &::aws_smithy_types::DateTime {
        &self.created_at
    }
    /// <p>The user who originally created the library item.</p>
    pub fn created_by(&self) -> &str {
        use std::ops::Deref;
        self.created_by.deref()
    }
    /// <p>The date and time the library item was last updated.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>The user who last updated the library item.</p>
    pub fn updated_by(&self) -> ::std::option::Option<&str> {
        self.updated_by.as_deref()
    }
    /// <p>The number of ratings the library item has received.</p>
    pub fn rating_count(&self) -> i32 {
        self.rating_count
    }
    /// <p>Whether the current user has rated the library item.</p>
    pub fn is_rated_by_user(&self) -> ::std::option::Option<bool> {
        self.is_rated_by_user
    }
    /// <p>The number of users who have the associated Q App.</p>
    pub fn user_count(&self) -> ::std::option::Option<i32> {
        self.user_count
    }
    /// <p>Indicates whether the library item has been verified.</p>
    pub fn is_verified(&self) -> ::std::option::Option<bool> {
        self.is_verified
    }
}
impl ::aws_types::request_id::RequestId for UpdateLibraryItemOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateLibraryItemOutput {
    /// Creates a new builder-style object to manufacture [`UpdateLibraryItemOutput`](crate::operation::update_library_item::UpdateLibraryItemOutput).
    pub fn builder() -> crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder {
        crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::default()
    }
}

/// A builder for [`UpdateLibraryItemOutput`](crate::operation::update_library_item::UpdateLibraryItemOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLibraryItemOutputBuilder {
    pub(crate) library_item_id: ::std::option::Option<::std::string::String>,
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) app_version: ::std::option::Option<i32>,
    pub(crate) categories: ::std::option::Option<::std::vec::Vec<crate::types::Category>>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) created_by: ::std::option::Option<::std::string::String>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_by: ::std::option::Option<::std::string::String>,
    pub(crate) rating_count: ::std::option::Option<i32>,
    pub(crate) is_rated_by_user: ::std::option::Option<bool>,
    pub(crate) user_count: ::std::option::Option<i32>,
    pub(crate) is_verified: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl UpdateLibraryItemOutputBuilder {
    /// <p>The unique identifier of the updated library item.</p>
    /// This field is required.
    pub fn library_item_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.library_item_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the updated library item.</p>
    pub fn set_library_item_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.library_item_id = input;
        self
    }
    /// <p>The unique identifier of the updated library item.</p>
    pub fn get_library_item_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.library_item_id
    }
    /// <p>The unique identifier of the Q App associated with the library item.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Q App associated with the library item.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The unique identifier of the Q App associated with the library item.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The version of the Q App associated with the library item.</p>
    /// This field is required.
    pub fn app_version(mut self, input: i32) -> Self {
        self.app_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The version of the Q App associated with the library item.</p>
    pub fn set_app_version(mut self, input: ::std::option::Option<i32>) -> Self {
        self.app_version = input;
        self
    }
    /// <p>The version of the Q App associated with the library item.</p>
    pub fn get_app_version(&self) -> &::std::option::Option<i32> {
        &self.app_version
    }
    /// Appends an item to `categories`.
    ///
    /// To override the contents of this collection use [`set_categories`](Self::set_categories).
    ///
    /// <p>The categories associated with the updated library item.</p>
    pub fn categories(mut self, input: crate::types::Category) -> Self {
        let mut v = self.categories.unwrap_or_default();
        v.push(input);
        self.categories = ::std::option::Option::Some(v);
        self
    }
    /// <p>The categories associated with the updated library item.</p>
    pub fn set_categories(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Category>>) -> Self {
        self.categories = input;
        self
    }
    /// <p>The categories associated with the updated library item.</p>
    pub fn get_categories(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Category>> {
        &self.categories
    }
    /// <p>The new status of the updated library item.</p>
    /// This field is required.
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The new status of the updated library item.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The new status of the updated library item.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The date and time the library item was originally created.</p>
    /// This field is required.
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the library item was originally created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time the library item was originally created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The user who originally created the library item.</p>
    /// This field is required.
    pub fn created_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user who originally created the library item.</p>
    pub fn set_created_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_by = input;
        self
    }
    /// <p>The user who originally created the library item.</p>
    pub fn get_created_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_by
    }
    /// <p>The date and time the library item was last updated.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the library item was last updated.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time the library item was last updated.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>The user who last updated the library item.</p>
    pub fn updated_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.updated_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user who last updated the library item.</p>
    pub fn set_updated_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.updated_by = input;
        self
    }
    /// <p>The user who last updated the library item.</p>
    pub fn get_updated_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.updated_by
    }
    /// <p>The number of ratings the library item has received.</p>
    /// This field is required.
    pub fn rating_count(mut self, input: i32) -> Self {
        self.rating_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of ratings the library item has received.</p>
    pub fn set_rating_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.rating_count = input;
        self
    }
    /// <p>The number of ratings the library item has received.</p>
    pub fn get_rating_count(&self) -> &::std::option::Option<i32> {
        &self.rating_count
    }
    /// <p>Whether the current user has rated the library item.</p>
    pub fn is_rated_by_user(mut self, input: bool) -> Self {
        self.is_rated_by_user = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether the current user has rated the library item.</p>
    pub fn set_is_rated_by_user(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_rated_by_user = input;
        self
    }
    /// <p>Whether the current user has rated the library item.</p>
    pub fn get_is_rated_by_user(&self) -> &::std::option::Option<bool> {
        &self.is_rated_by_user
    }
    /// <p>The number of users who have the associated Q App.</p>
    pub fn user_count(mut self, input: i32) -> Self {
        self.user_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of users who have the associated Q App.</p>
    pub fn set_user_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.user_count = input;
        self
    }
    /// <p>The number of users who have the associated Q App.</p>
    pub fn get_user_count(&self) -> &::std::option::Option<i32> {
        &self.user_count
    }
    /// <p>Indicates whether the library item has been verified.</p>
    pub fn is_verified(mut self, input: bool) -> Self {
        self.is_verified = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the library item has been verified.</p>
    pub fn set_is_verified(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_verified = input;
        self
    }
    /// <p>Indicates whether the library item has been verified.</p>
    pub fn get_is_verified(&self) -> &::std::option::Option<bool> {
        &self.is_verified
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateLibraryItemOutput`](crate::operation::update_library_item::UpdateLibraryItemOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`library_item_id`](crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::library_item_id)
    /// - [`app_id`](crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::app_id)
    /// - [`app_version`](crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::app_version)
    /// - [`categories`](crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::categories)
    /// - [`status`](crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::status)
    /// - [`created_at`](crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::created_at)
    /// - [`created_by`](crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::created_by)
    /// - [`rating_count`](crate::operation::update_library_item::builders::UpdateLibraryItemOutputBuilder::rating_count)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_library_item::UpdateLibraryItemOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_library_item::UpdateLibraryItemOutput {
            library_item_id: self.library_item_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "library_item_id",
                    "library_item_id was not specified but it is required when building UpdateLibraryItemOutput",
                )
            })?,
            app_id: self.app_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_id",
                    "app_id was not specified but it is required when building UpdateLibraryItemOutput",
                )
            })?,
            app_version: self.app_version.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "app_version",
                    "app_version was not specified but it is required when building UpdateLibraryItemOutput",
                )
            })?,
            categories: self.categories.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "categories",
                    "categories was not specified but it is required when building UpdateLibraryItemOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building UpdateLibraryItemOutput",
                )
            })?,
            created_at: self.created_at.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_at",
                    "created_at was not specified but it is required when building UpdateLibraryItemOutput",
                )
            })?,
            created_by: self.created_by.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "created_by",
                    "created_by was not specified but it is required when building UpdateLibraryItemOutput",
                )
            })?,
            updated_at: self.updated_at,
            updated_by: self.updated_by,
            rating_count: self.rating_count.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "rating_count",
                    "rating_count was not specified but it is required when building UpdateLibraryItemOutput",
                )
            })?,
            is_rated_by_user: self.is_rated_by_user,
            user_count: self.user_count,
            is_verified: self.is_verified,
            _request_id: self._request_id,
        })
    }
}
