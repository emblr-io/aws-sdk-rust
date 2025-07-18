// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns information about the location of a change or comment in the comparison between two commits or a pull request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Location {
    /// <p>The name of the file being compared, including its extension and subdirectory, if any.</p>
    pub file_path: ::std::option::Option<::std::string::String>,
    /// <p>The position of a change in a compared file, in line number format.</p>
    pub file_position: ::std::option::Option<i64>,
    /// <p>In a comparison of commits or a pull request, whether the change is in the before or after of that comparison.</p>
    pub relative_file_version: ::std::option::Option<crate::types::RelativeFileVersionEnum>,
}
impl Location {
    /// <p>The name of the file being compared, including its extension and subdirectory, if any.</p>
    pub fn file_path(&self) -> ::std::option::Option<&str> {
        self.file_path.as_deref()
    }
    /// <p>The position of a change in a compared file, in line number format.</p>
    pub fn file_position(&self) -> ::std::option::Option<i64> {
        self.file_position
    }
    /// <p>In a comparison of commits or a pull request, whether the change is in the before or after of that comparison.</p>
    pub fn relative_file_version(&self) -> ::std::option::Option<&crate::types::RelativeFileVersionEnum> {
        self.relative_file_version.as_ref()
    }
}
impl Location {
    /// Creates a new builder-style object to manufacture [`Location`](crate::types::Location).
    pub fn builder() -> crate::types::builders::LocationBuilder {
        crate::types::builders::LocationBuilder::default()
    }
}

/// A builder for [`Location`](crate::types::Location).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LocationBuilder {
    pub(crate) file_path: ::std::option::Option<::std::string::String>,
    pub(crate) file_position: ::std::option::Option<i64>,
    pub(crate) relative_file_version: ::std::option::Option<crate::types::RelativeFileVersionEnum>,
}
impl LocationBuilder {
    /// <p>The name of the file being compared, including its extension and subdirectory, if any.</p>
    pub fn file_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the file being compared, including its extension and subdirectory, if any.</p>
    pub fn set_file_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_path = input;
        self
    }
    /// <p>The name of the file being compared, including its extension and subdirectory, if any.</p>
    pub fn get_file_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_path
    }
    /// <p>The position of a change in a compared file, in line number format.</p>
    pub fn file_position(mut self, input: i64) -> Self {
        self.file_position = ::std::option::Option::Some(input);
        self
    }
    /// <p>The position of a change in a compared file, in line number format.</p>
    pub fn set_file_position(mut self, input: ::std::option::Option<i64>) -> Self {
        self.file_position = input;
        self
    }
    /// <p>The position of a change in a compared file, in line number format.</p>
    pub fn get_file_position(&self) -> &::std::option::Option<i64> {
        &self.file_position
    }
    /// <p>In a comparison of commits or a pull request, whether the change is in the before or after of that comparison.</p>
    pub fn relative_file_version(mut self, input: crate::types::RelativeFileVersionEnum) -> Self {
        self.relative_file_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>In a comparison of commits or a pull request, whether the change is in the before or after of that comparison.</p>
    pub fn set_relative_file_version(mut self, input: ::std::option::Option<crate::types::RelativeFileVersionEnum>) -> Self {
        self.relative_file_version = input;
        self
    }
    /// <p>In a comparison of commits or a pull request, whether the change is in the before or after of that comparison.</p>
    pub fn get_relative_file_version(&self) -> &::std::option::Option<crate::types::RelativeFileVersionEnum> {
        &self.relative_file_version
    }
    /// Consumes the builder and constructs a [`Location`](crate::types::Location).
    pub fn build(self) -> crate::types::Location {
        crate::types::Location {
            file_path: self.file_path,
            file_position: self.file_position,
            relative_file_version: self.relative_file_version,
        }
    }
}
