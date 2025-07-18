// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisableDirectoryOutput {
    /// <p>The ARN of the directory that has been disabled.</p>
    pub directory_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl DisableDirectoryOutput {
    /// <p>The ARN of the directory that has been disabled.</p>
    pub fn directory_arn(&self) -> &str {
        use std::ops::Deref;
        self.directory_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for DisableDirectoryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DisableDirectoryOutput {
    /// Creates a new builder-style object to manufacture [`DisableDirectoryOutput`](crate::operation::disable_directory::DisableDirectoryOutput).
    pub fn builder() -> crate::operation::disable_directory::builders::DisableDirectoryOutputBuilder {
        crate::operation::disable_directory::builders::DisableDirectoryOutputBuilder::default()
    }
}

/// A builder for [`DisableDirectoryOutput`](crate::operation::disable_directory::DisableDirectoryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisableDirectoryOutputBuilder {
    pub(crate) directory_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DisableDirectoryOutputBuilder {
    /// <p>The ARN of the directory that has been disabled.</p>
    /// This field is required.
    pub fn directory_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.directory_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the directory that has been disabled.</p>
    pub fn set_directory_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.directory_arn = input;
        self
    }
    /// <p>The ARN of the directory that has been disabled.</p>
    pub fn get_directory_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.directory_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DisableDirectoryOutput`](crate::operation::disable_directory::DisableDirectoryOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`directory_arn`](crate::operation::disable_directory::builders::DisableDirectoryOutputBuilder::directory_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::disable_directory::DisableDirectoryOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::disable_directory::DisableDirectoryOutput {
            directory_arn: self.directory_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "directory_arn",
                    "directory_arn was not specified but it is required when building DisableDirectoryOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
