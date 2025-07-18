// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the results of the <code>GetDirectoryLimits</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetDirectoryLimitsOutput {
    /// <p>A <code>DirectoryLimits</code> object that contains the directory limits for the current Region.</p>
    pub directory_limits: ::std::option::Option<crate::types::DirectoryLimits>,
    _request_id: Option<String>,
}
impl GetDirectoryLimitsOutput {
    /// <p>A <code>DirectoryLimits</code> object that contains the directory limits for the current Region.</p>
    pub fn directory_limits(&self) -> ::std::option::Option<&crate::types::DirectoryLimits> {
        self.directory_limits.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetDirectoryLimitsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetDirectoryLimitsOutput {
    /// Creates a new builder-style object to manufacture [`GetDirectoryLimitsOutput`](crate::operation::get_directory_limits::GetDirectoryLimitsOutput).
    pub fn builder() -> crate::operation::get_directory_limits::builders::GetDirectoryLimitsOutputBuilder {
        crate::operation::get_directory_limits::builders::GetDirectoryLimitsOutputBuilder::default()
    }
}

/// A builder for [`GetDirectoryLimitsOutput`](crate::operation::get_directory_limits::GetDirectoryLimitsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetDirectoryLimitsOutputBuilder {
    pub(crate) directory_limits: ::std::option::Option<crate::types::DirectoryLimits>,
    _request_id: Option<String>,
}
impl GetDirectoryLimitsOutputBuilder {
    /// <p>A <code>DirectoryLimits</code> object that contains the directory limits for the current Region.</p>
    pub fn directory_limits(mut self, input: crate::types::DirectoryLimits) -> Self {
        self.directory_limits = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>DirectoryLimits</code> object that contains the directory limits for the current Region.</p>
    pub fn set_directory_limits(mut self, input: ::std::option::Option<crate::types::DirectoryLimits>) -> Self {
        self.directory_limits = input;
        self
    }
    /// <p>A <code>DirectoryLimits</code> object that contains the directory limits for the current Region.</p>
    pub fn get_directory_limits(&self) -> &::std::option::Option<crate::types::DirectoryLimits> {
        &self.directory_limits
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetDirectoryLimitsOutput`](crate::operation::get_directory_limits::GetDirectoryLimitsOutput).
    pub fn build(self) -> crate::operation::get_directory_limits::GetDirectoryLimitsOutput {
        crate::operation::get_directory_limits::GetDirectoryLimitsOutput {
            directory_limits: self.directory_limits,
            _request_id: self._request_id,
        }
    }
}
