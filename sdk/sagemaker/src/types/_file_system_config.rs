// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon Elastic File System storage configuration for a SageMaker AI image.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FileSystemConfig {
    /// <p>The path within the image to mount the user's EFS home directory. The directory should be empty. If not specified, defaults to <i>/home/sagemaker-user</i>.</p>
    pub mount_path: ::std::option::Option<::std::string::String>,
    /// <p>The default POSIX user ID (UID). If not specified, defaults to <code>1000</code>.</p>
    pub default_uid: ::std::option::Option<i32>,
    /// <p>The default POSIX group ID (GID). If not specified, defaults to <code>100</code>.</p>
    pub default_gid: ::std::option::Option<i32>,
}
impl FileSystemConfig {
    /// <p>The path within the image to mount the user's EFS home directory. The directory should be empty. If not specified, defaults to <i>/home/sagemaker-user</i>.</p>
    pub fn mount_path(&self) -> ::std::option::Option<&str> {
        self.mount_path.as_deref()
    }
    /// <p>The default POSIX user ID (UID). If not specified, defaults to <code>1000</code>.</p>
    pub fn default_uid(&self) -> ::std::option::Option<i32> {
        self.default_uid
    }
    /// <p>The default POSIX group ID (GID). If not specified, defaults to <code>100</code>.</p>
    pub fn default_gid(&self) -> ::std::option::Option<i32> {
        self.default_gid
    }
}
impl FileSystemConfig {
    /// Creates a new builder-style object to manufacture [`FileSystemConfig`](crate::types::FileSystemConfig).
    pub fn builder() -> crate::types::builders::FileSystemConfigBuilder {
        crate::types::builders::FileSystemConfigBuilder::default()
    }
}

/// A builder for [`FileSystemConfig`](crate::types::FileSystemConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FileSystemConfigBuilder {
    pub(crate) mount_path: ::std::option::Option<::std::string::String>,
    pub(crate) default_uid: ::std::option::Option<i32>,
    pub(crate) default_gid: ::std::option::Option<i32>,
}
impl FileSystemConfigBuilder {
    /// <p>The path within the image to mount the user's EFS home directory. The directory should be empty. If not specified, defaults to <i>/home/sagemaker-user</i>.</p>
    pub fn mount_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.mount_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path within the image to mount the user's EFS home directory. The directory should be empty. If not specified, defaults to <i>/home/sagemaker-user</i>.</p>
    pub fn set_mount_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.mount_path = input;
        self
    }
    /// <p>The path within the image to mount the user's EFS home directory. The directory should be empty. If not specified, defaults to <i>/home/sagemaker-user</i>.</p>
    pub fn get_mount_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.mount_path
    }
    /// <p>The default POSIX user ID (UID). If not specified, defaults to <code>1000</code>.</p>
    pub fn default_uid(mut self, input: i32) -> Self {
        self.default_uid = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default POSIX user ID (UID). If not specified, defaults to <code>1000</code>.</p>
    pub fn set_default_uid(mut self, input: ::std::option::Option<i32>) -> Self {
        self.default_uid = input;
        self
    }
    /// <p>The default POSIX user ID (UID). If not specified, defaults to <code>1000</code>.</p>
    pub fn get_default_uid(&self) -> &::std::option::Option<i32> {
        &self.default_uid
    }
    /// <p>The default POSIX group ID (GID). If not specified, defaults to <code>100</code>.</p>
    pub fn default_gid(mut self, input: i32) -> Self {
        self.default_gid = ::std::option::Option::Some(input);
        self
    }
    /// <p>The default POSIX group ID (GID). If not specified, defaults to <code>100</code>.</p>
    pub fn set_default_gid(mut self, input: ::std::option::Option<i32>) -> Self {
        self.default_gid = input;
        self
    }
    /// <p>The default POSIX group ID (GID). If not specified, defaults to <code>100</code>.</p>
    pub fn get_default_gid(&self) -> &::std::option::Option<i32> {
        &self.default_gid
    }
    /// Consumes the builder and constructs a [`FileSystemConfig`](crate::types::FileSystemConfig).
    pub fn build(self) -> crate::types::FileSystemConfig {
        crate::types::FileSystemConfig {
            mount_path: self.mount_path,
            default_uid: self.default_uid,
            default_gid: self.default_gid,
        }
    }
}
