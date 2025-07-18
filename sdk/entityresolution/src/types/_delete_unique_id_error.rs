// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Delete Unique Id error.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUniqueIdError {
    /// <p>The unique ID that could not be deleted.</p>
    pub unique_id: ::std::string::String,
    /// <p>The error type for the batch delete unique ID operation.</p>
    pub error_type: crate::types::DeleteUniqueIdErrorType,
}
impl DeleteUniqueIdError {
    /// <p>The unique ID that could not be deleted.</p>
    pub fn unique_id(&self) -> &str {
        use std::ops::Deref;
        self.unique_id.deref()
    }
    /// <p>The error type for the batch delete unique ID operation.</p>
    pub fn error_type(&self) -> &crate::types::DeleteUniqueIdErrorType {
        &self.error_type
    }
}
impl DeleteUniqueIdError {
    /// Creates a new builder-style object to manufacture [`DeleteUniqueIdError`](crate::types::DeleteUniqueIdError).
    pub fn builder() -> crate::types::builders::DeleteUniqueIdErrorBuilder {
        crate::types::builders::DeleteUniqueIdErrorBuilder::default()
    }
}

/// A builder for [`DeleteUniqueIdError`](crate::types::DeleteUniqueIdError).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteUniqueIdErrorBuilder {
    pub(crate) unique_id: ::std::option::Option<::std::string::String>,
    pub(crate) error_type: ::std::option::Option<crate::types::DeleteUniqueIdErrorType>,
}
impl DeleteUniqueIdErrorBuilder {
    /// <p>The unique ID that could not be deleted.</p>
    /// This field is required.
    pub fn unique_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.unique_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID that could not be deleted.</p>
    pub fn set_unique_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.unique_id = input;
        self
    }
    /// <p>The unique ID that could not be deleted.</p>
    pub fn get_unique_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.unique_id
    }
    /// <p>The error type for the batch delete unique ID operation.</p>
    /// This field is required.
    pub fn error_type(mut self, input: crate::types::DeleteUniqueIdErrorType) -> Self {
        self.error_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The error type for the batch delete unique ID operation.</p>
    pub fn set_error_type(mut self, input: ::std::option::Option<crate::types::DeleteUniqueIdErrorType>) -> Self {
        self.error_type = input;
        self
    }
    /// <p>The error type for the batch delete unique ID operation.</p>
    pub fn get_error_type(&self) -> &::std::option::Option<crate::types::DeleteUniqueIdErrorType> {
        &self.error_type
    }
    /// Consumes the builder and constructs a [`DeleteUniqueIdError`](crate::types::DeleteUniqueIdError).
    /// This method will fail if any of the following fields are not set:
    /// - [`unique_id`](crate::types::builders::DeleteUniqueIdErrorBuilder::unique_id)
    /// - [`error_type`](crate::types::builders::DeleteUniqueIdErrorBuilder::error_type)
    pub fn build(self) -> ::std::result::Result<crate::types::DeleteUniqueIdError, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DeleteUniqueIdError {
            unique_id: self.unique_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "unique_id",
                    "unique_id was not specified but it is required when building DeleteUniqueIdError",
                )
            })?,
            error_type: self.error_type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "error_type",
                    "error_type was not specified but it is required when building DeleteUniqueIdError",
                )
            })?,
        })
    }
}
