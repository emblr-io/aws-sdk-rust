// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details of the response from code interpreter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct OutputFile {
    /// <p>The name of the file containing response from code interpreter.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of file that contains response from the code interpreter.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The byte count of files that contains response from code interpreter.</p>
    pub bytes: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl OutputFile {
    /// <p>The name of the file containing response from code interpreter.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of file that contains response from the code interpreter.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The byte count of files that contains response from code interpreter.</p>
    pub fn bytes(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.bytes.as_ref()
    }
}
impl ::std::fmt::Debug for OutputFile {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OutputFile");
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("r#type", &"*** Sensitive Data Redacted ***");
        formatter.field("bytes", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl OutputFile {
    /// Creates a new builder-style object to manufacture [`OutputFile`](crate::types::OutputFile).
    pub fn builder() -> crate::types::builders::OutputFileBuilder {
        crate::types::builders::OutputFileBuilder::default()
    }
}

/// A builder for [`OutputFile`](crate::types::OutputFile).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct OutputFileBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) bytes: ::std::option::Option<::aws_smithy_types::Blob>,
}
impl OutputFileBuilder {
    /// <p>The name of the file containing response from code interpreter.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the file containing response from code interpreter.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the file containing response from code interpreter.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of file that contains response from the code interpreter.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of file that contains response from the code interpreter.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of file that contains response from the code interpreter.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The byte count of files that contains response from code interpreter.</p>
    pub fn bytes(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The byte count of files that contains response from code interpreter.</p>
    pub fn set_bytes(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.bytes = input;
        self
    }
    /// <p>The byte count of files that contains response from code interpreter.</p>
    pub fn get_bytes(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.bytes
    }
    /// Consumes the builder and constructs a [`OutputFile`](crate::types::OutputFile).
    pub fn build(self) -> crate::types::OutputFile {
        crate::types::OutputFile {
            name: self.name,
            r#type: self.r#type,
            bytes: self.bytes,
        }
    }
}
impl ::std::fmt::Debug for OutputFileBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OutputFileBuilder");
        formatter.field("name", &"*** Sensitive Data Redacted ***");
        formatter.field("r#type", &"*** Sensitive Data Redacted ***");
        formatter.field("bytes", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
