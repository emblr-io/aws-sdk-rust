// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchAddRoleOutput {
    /// <p>An array of successfully updated accessor identifiers.</p>
    pub added_accessor_ids: ::std::vec::Vec<::std::string::String>,
    /// <p>An array of errors that occurred when roles were added.</p>
    pub errors: ::std::vec::Vec<crate::types::BatchError>,
    _request_id: Option<String>,
}
impl BatchAddRoleOutput {
    /// <p>An array of successfully updated accessor identifiers.</p>
    pub fn added_accessor_ids(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.added_accessor_ids.deref()
    }
    /// <p>An array of errors that occurred when roles were added.</p>
    pub fn errors(&self) -> &[crate::types::BatchError] {
        use std::ops::Deref;
        self.errors.deref()
    }
}
impl ::aws_types::request_id::RequestId for BatchAddRoleOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchAddRoleOutput {
    /// Creates a new builder-style object to manufacture [`BatchAddRoleOutput`](crate::operation::batch_add_role::BatchAddRoleOutput).
    pub fn builder() -> crate::operation::batch_add_role::builders::BatchAddRoleOutputBuilder {
        crate::operation::batch_add_role::builders::BatchAddRoleOutputBuilder::default()
    }
}

/// A builder for [`BatchAddRoleOutput`](crate::operation::batch_add_role::BatchAddRoleOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchAddRoleOutputBuilder {
    pub(crate) added_accessor_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchError>>,
    _request_id: Option<String>,
}
impl BatchAddRoleOutputBuilder {
    /// Appends an item to `added_accessor_ids`.
    ///
    /// To override the contents of this collection use [`set_added_accessor_ids`](Self::set_added_accessor_ids).
    ///
    /// <p>An array of successfully updated accessor identifiers.</p>
    pub fn added_accessor_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.added_accessor_ids.unwrap_or_default();
        v.push(input.into());
        self.added_accessor_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of successfully updated accessor identifiers.</p>
    pub fn set_added_accessor_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.added_accessor_ids = input;
        self
    }
    /// <p>An array of successfully updated accessor identifiers.</p>
    pub fn get_added_accessor_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.added_accessor_ids
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>An array of errors that occurred when roles were added.</p>
    pub fn errors(mut self, input: crate::types::BatchError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of errors that occurred when roles were added.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BatchError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>An array of errors that occurred when roles were added.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchError>> {
        &self.errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchAddRoleOutput`](crate::operation::batch_add_role::BatchAddRoleOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`added_accessor_ids`](crate::operation::batch_add_role::builders::BatchAddRoleOutputBuilder::added_accessor_ids)
    /// - [`errors`](crate::operation::batch_add_role::builders::BatchAddRoleOutputBuilder::errors)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_add_role::BatchAddRoleOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::batch_add_role::BatchAddRoleOutput {
            added_accessor_ids: self.added_accessor_ids.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "added_accessor_ids",
                    "added_accessor_ids was not specified but it is required when building BatchAddRoleOutput",
                )
            })?,
            errors: self.errors.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "errors",
                    "errors was not specified but it is required when building BatchAddRoleOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
