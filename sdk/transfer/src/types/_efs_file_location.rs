// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the details for the file location for the file that's being used in the workflow. Only applicable if you are using Amazon Elastic File Systems (Amazon EFS) for storage.</p>
/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EfsFileLocation {
    /// <p>The identifier of the file system, assigned by Amazon EFS.</p>
    pub file_system_id: ::std::option::Option<::std::string::String>,
    /// <p>The pathname for the folder being used by a workflow.</p>
    pub path: ::std::option::Option<::std::string::String>,
}
impl EfsFileLocation {
    /// <p>The identifier of the file system, assigned by Amazon EFS.</p>
    pub fn file_system_id(&self) -> ::std::option::Option<&str> {
        self.file_system_id.as_deref()
    }
    /// <p>The pathname for the folder being used by a workflow.</p>
    pub fn path(&self) -> ::std::option::Option<&str> {
        self.path.as_deref()
    }
}
impl EfsFileLocation {
    /// Creates a new builder-style object to manufacture [`EfsFileLocation`](crate::types::EfsFileLocation).
    pub fn builder() -> crate::types::builders::EfsFileLocationBuilder {
        crate::types::builders::EfsFileLocationBuilder::default()
    }
}

/// A builder for [`EfsFileLocation`](crate::types::EfsFileLocation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EfsFileLocationBuilder {
    pub(crate) file_system_id: ::std::option::Option<::std::string::String>,
    pub(crate) path: ::std::option::Option<::std::string::String>,
}
impl EfsFileLocationBuilder {
    /// <p>The identifier of the file system, assigned by Amazon EFS.</p>
    pub fn file_system_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the file system, assigned by Amazon EFS.</p>
    pub fn set_file_system_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_id = input;
        self
    }
    /// <p>The identifier of the file system, assigned by Amazon EFS.</p>
    pub fn get_file_system_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_id
    }
    /// <p>The pathname for the folder being used by a workflow.</p>
    pub fn path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pathname for the folder being used by a workflow.</p>
    pub fn set_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path = input;
        self
    }
    /// <p>The pathname for the folder being used by a workflow.</p>
    pub fn get_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.path
    }
    /// Consumes the builder and constructs a [`EfsFileLocation`](crate::types::EfsFileLocation).
    pub fn build(self) -> crate::types::EfsFileLocation {
        crate::types::EfsFileLocation {
            file_system_id: self.file_system_id,
            path: self.path,
        }
    }
}
