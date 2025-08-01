// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The request object for <code>DeleteFileSystem</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteFileSystemInput {
    /// <p>The ID of the file system that you want to delete.</p>
    pub file_system_id: ::std::option::Option<::std::string::String>,
    /// <p>A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent deletion. This token is automatically filled on your behalf when using the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub client_request_token: ::std::option::Option<::std::string::String>,
    /// <p>The configuration object for the Microsoft Windows file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub windows_configuration: ::std::option::Option<crate::types::DeleteFileSystemWindowsConfiguration>,
    /// <p>The configuration object for the Amazon FSx for Lustre file system being deleted in the <code>DeleteFileSystem</code> operation.</p>
    pub lustre_configuration: ::std::option::Option<crate::types::DeleteFileSystemLustreConfiguration>,
    /// <p>The configuration object for the OpenZFS file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub open_zfs_configuration: ::std::option::Option<crate::types::DeleteFileSystemOpenZfsConfiguration>,
}
impl DeleteFileSystemInput {
    /// <p>The ID of the file system that you want to delete.</p>
    pub fn file_system_id(&self) -> ::std::option::Option<&str> {
        self.file_system_id.as_deref()
    }
    /// <p>A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent deletion. This token is automatically filled on your behalf when using the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(&self) -> ::std::option::Option<&str> {
        self.client_request_token.as_deref()
    }
    /// <p>The configuration object for the Microsoft Windows file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub fn windows_configuration(&self) -> ::std::option::Option<&crate::types::DeleteFileSystemWindowsConfiguration> {
        self.windows_configuration.as_ref()
    }
    /// <p>The configuration object for the Amazon FSx for Lustre file system being deleted in the <code>DeleteFileSystem</code> operation.</p>
    pub fn lustre_configuration(&self) -> ::std::option::Option<&crate::types::DeleteFileSystemLustreConfiguration> {
        self.lustre_configuration.as_ref()
    }
    /// <p>The configuration object for the OpenZFS file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub fn open_zfs_configuration(&self) -> ::std::option::Option<&crate::types::DeleteFileSystemOpenZfsConfiguration> {
        self.open_zfs_configuration.as_ref()
    }
}
impl DeleteFileSystemInput {
    /// Creates a new builder-style object to manufacture [`DeleteFileSystemInput`](crate::operation::delete_file_system::DeleteFileSystemInput).
    pub fn builder() -> crate::operation::delete_file_system::builders::DeleteFileSystemInputBuilder {
        crate::operation::delete_file_system::builders::DeleteFileSystemInputBuilder::default()
    }
}

/// A builder for [`DeleteFileSystemInput`](crate::operation::delete_file_system::DeleteFileSystemInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteFileSystemInputBuilder {
    pub(crate) file_system_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_request_token: ::std::option::Option<::std::string::String>,
    pub(crate) windows_configuration: ::std::option::Option<crate::types::DeleteFileSystemWindowsConfiguration>,
    pub(crate) lustre_configuration: ::std::option::Option<crate::types::DeleteFileSystemLustreConfiguration>,
    pub(crate) open_zfs_configuration: ::std::option::Option<crate::types::DeleteFileSystemOpenZfsConfiguration>,
}
impl DeleteFileSystemInputBuilder {
    /// <p>The ID of the file system that you want to delete.</p>
    /// This field is required.
    pub fn file_system_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the file system that you want to delete.</p>
    pub fn set_file_system_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_id = input;
        self
    }
    /// <p>The ID of the file system that you want to delete.</p>
    pub fn get_file_system_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_id
    }
    /// <p>A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent deletion. This token is automatically filled on your behalf when using the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn client_request_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_request_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent deletion. This token is automatically filled on your behalf when using the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn set_client_request_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_request_token = input;
        self
    }
    /// <p>A string of up to 63 ASCII characters that Amazon FSx uses to ensure idempotent deletion. This token is automatically filled on your behalf when using the Command Line Interface (CLI) or an Amazon Web Services SDK.</p>
    pub fn get_client_request_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_request_token
    }
    /// <p>The configuration object for the Microsoft Windows file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub fn windows_configuration(mut self, input: crate::types::DeleteFileSystemWindowsConfiguration) -> Self {
        self.windows_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration object for the Microsoft Windows file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub fn set_windows_configuration(mut self, input: ::std::option::Option<crate::types::DeleteFileSystemWindowsConfiguration>) -> Self {
        self.windows_configuration = input;
        self
    }
    /// <p>The configuration object for the Microsoft Windows file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub fn get_windows_configuration(&self) -> &::std::option::Option<crate::types::DeleteFileSystemWindowsConfiguration> {
        &self.windows_configuration
    }
    /// <p>The configuration object for the Amazon FSx for Lustre file system being deleted in the <code>DeleteFileSystem</code> operation.</p>
    pub fn lustre_configuration(mut self, input: crate::types::DeleteFileSystemLustreConfiguration) -> Self {
        self.lustre_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration object for the Amazon FSx for Lustre file system being deleted in the <code>DeleteFileSystem</code> operation.</p>
    pub fn set_lustre_configuration(mut self, input: ::std::option::Option<crate::types::DeleteFileSystemLustreConfiguration>) -> Self {
        self.lustre_configuration = input;
        self
    }
    /// <p>The configuration object for the Amazon FSx for Lustre file system being deleted in the <code>DeleteFileSystem</code> operation.</p>
    pub fn get_lustre_configuration(&self) -> &::std::option::Option<crate::types::DeleteFileSystemLustreConfiguration> {
        &self.lustre_configuration
    }
    /// <p>The configuration object for the OpenZFS file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub fn open_zfs_configuration(mut self, input: crate::types::DeleteFileSystemOpenZfsConfiguration) -> Self {
        self.open_zfs_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration object for the OpenZFS file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub fn set_open_zfs_configuration(mut self, input: ::std::option::Option<crate::types::DeleteFileSystemOpenZfsConfiguration>) -> Self {
        self.open_zfs_configuration = input;
        self
    }
    /// <p>The configuration object for the OpenZFS file system used in the <code>DeleteFileSystem</code> operation.</p>
    pub fn get_open_zfs_configuration(&self) -> &::std::option::Option<crate::types::DeleteFileSystemOpenZfsConfiguration> {
        &self.open_zfs_configuration
    }
    /// Consumes the builder and constructs a [`DeleteFileSystemInput`](crate::operation::delete_file_system::DeleteFileSystemInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_file_system::DeleteFileSystemInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_file_system::DeleteFileSystemInput {
            file_system_id: self.file_system_id,
            client_request_token: self.client_request_token,
            windows_configuration: self.windows_configuration,
            lustre_configuration: self.lustre_configuration,
            open_zfs_configuration: self.open_zfs_configuration,
        })
    }
}
