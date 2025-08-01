// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AssociateFileSystemOutput {
    /// <p>The ARN of the newly created file system association.</p>
    pub file_system_association_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl AssociateFileSystemOutput {
    /// <p>The ARN of the newly created file system association.</p>
    pub fn file_system_association_arn(&self) -> ::std::option::Option<&str> {
        self.file_system_association_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for AssociateFileSystemOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl AssociateFileSystemOutput {
    /// Creates a new builder-style object to manufacture [`AssociateFileSystemOutput`](crate::operation::associate_file_system::AssociateFileSystemOutput).
    pub fn builder() -> crate::operation::associate_file_system::builders::AssociateFileSystemOutputBuilder {
        crate::operation::associate_file_system::builders::AssociateFileSystemOutputBuilder::default()
    }
}

/// A builder for [`AssociateFileSystemOutput`](crate::operation::associate_file_system::AssociateFileSystemOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AssociateFileSystemOutputBuilder {
    pub(crate) file_system_association_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl AssociateFileSystemOutputBuilder {
    /// <p>The ARN of the newly created file system association.</p>
    pub fn file_system_association_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_association_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the newly created file system association.</p>
    pub fn set_file_system_association_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_association_arn = input;
        self
    }
    /// <p>The ARN of the newly created file system association.</p>
    pub fn get_file_system_association_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_association_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`AssociateFileSystemOutput`](crate::operation::associate_file_system::AssociateFileSystemOutput).
    pub fn build(self) -> crate::operation::associate_file_system::AssociateFileSystemOutput {
        crate::operation::associate_file_system::AssociateFileSystemOutput {
            file_system_association_arn: self.file_system_association_arn,
            _request_id: self._request_id,
        }
    }
}
