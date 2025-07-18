// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteBuildBatchOutput {
    /// <p>The status code.</p>
    pub status_code: ::std::option::Option<::std::string::String>,
    /// <p>An array of strings that contain the identifiers of the builds that were deleted.</p>
    pub builds_deleted: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An array of <code>BuildNotDeleted</code> objects that specify the builds that could not be deleted.</p>
    pub builds_not_deleted: ::std::option::Option<::std::vec::Vec<crate::types::BuildNotDeleted>>,
    _request_id: Option<String>,
}
impl DeleteBuildBatchOutput {
    /// <p>The status code.</p>
    pub fn status_code(&self) -> ::std::option::Option<&str> {
        self.status_code.as_deref()
    }
    /// <p>An array of strings that contain the identifiers of the builds that were deleted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.builds_deleted.is_none()`.
    pub fn builds_deleted(&self) -> &[::std::string::String] {
        self.builds_deleted.as_deref().unwrap_or_default()
    }
    /// <p>An array of <code>BuildNotDeleted</code> objects that specify the builds that could not be deleted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.builds_not_deleted.is_none()`.
    pub fn builds_not_deleted(&self) -> &[crate::types::BuildNotDeleted] {
        self.builds_not_deleted.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DeleteBuildBatchOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteBuildBatchOutput {
    /// Creates a new builder-style object to manufacture [`DeleteBuildBatchOutput`](crate::operation::delete_build_batch::DeleteBuildBatchOutput).
    pub fn builder() -> crate::operation::delete_build_batch::builders::DeleteBuildBatchOutputBuilder {
        crate::operation::delete_build_batch::builders::DeleteBuildBatchOutputBuilder::default()
    }
}

/// A builder for [`DeleteBuildBatchOutput`](crate::operation::delete_build_batch::DeleteBuildBatchOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteBuildBatchOutputBuilder {
    pub(crate) status_code: ::std::option::Option<::std::string::String>,
    pub(crate) builds_deleted: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) builds_not_deleted: ::std::option::Option<::std::vec::Vec<crate::types::BuildNotDeleted>>,
    _request_id: Option<String>,
}
impl DeleteBuildBatchOutputBuilder {
    /// <p>The status code.</p>
    pub fn status_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status code.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The status code.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_code
    }
    /// Appends an item to `builds_deleted`.
    ///
    /// To override the contents of this collection use [`set_builds_deleted`](Self::set_builds_deleted).
    ///
    /// <p>An array of strings that contain the identifiers of the builds that were deleted.</p>
    pub fn builds_deleted(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.builds_deleted.unwrap_or_default();
        v.push(input.into());
        self.builds_deleted = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of strings that contain the identifiers of the builds that were deleted.</p>
    pub fn set_builds_deleted(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.builds_deleted = input;
        self
    }
    /// <p>An array of strings that contain the identifiers of the builds that were deleted.</p>
    pub fn get_builds_deleted(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.builds_deleted
    }
    /// Appends an item to `builds_not_deleted`.
    ///
    /// To override the contents of this collection use [`set_builds_not_deleted`](Self::set_builds_not_deleted).
    ///
    /// <p>An array of <code>BuildNotDeleted</code> objects that specify the builds that could not be deleted.</p>
    pub fn builds_not_deleted(mut self, input: crate::types::BuildNotDeleted) -> Self {
        let mut v = self.builds_not_deleted.unwrap_or_default();
        v.push(input);
        self.builds_not_deleted = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>BuildNotDeleted</code> objects that specify the builds that could not be deleted.</p>
    pub fn set_builds_not_deleted(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BuildNotDeleted>>) -> Self {
        self.builds_not_deleted = input;
        self
    }
    /// <p>An array of <code>BuildNotDeleted</code> objects that specify the builds that could not be deleted.</p>
    pub fn get_builds_not_deleted(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BuildNotDeleted>> {
        &self.builds_not_deleted
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteBuildBatchOutput`](crate::operation::delete_build_batch::DeleteBuildBatchOutput).
    pub fn build(self) -> crate::operation::delete_build_batch::DeleteBuildBatchOutput {
        crate::operation::delete_build_batch::DeleteBuildBatchOutput {
            status_code: self.status_code,
            builds_deleted: self.builds_deleted,
            builds_not_deleted: self.builds_not_deleted,
            _request_id: self._request_id,
        }
    }
}
