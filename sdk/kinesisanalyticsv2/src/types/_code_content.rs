// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies either the application code, or the location of the application code, for a Managed Service for Apache Flink application.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodeContent {
    /// <p>The text-format code for a Managed Service for Apache Flink application.</p>
    pub text_content: ::std::option::Option<::std::string::String>,
    /// <p>The zip-format code for a Managed Service for Apache Flink application.</p>
    pub zip_file_content: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>Information about the Amazon S3 bucket that contains the application code.</p>
    pub s3_content_location: ::std::option::Option<crate::types::S3ContentLocation>,
}
impl CodeContent {
    /// <p>The text-format code for a Managed Service for Apache Flink application.</p>
    pub fn text_content(&self) -> ::std::option::Option<&str> {
        self.text_content.as_deref()
    }
    /// <p>The zip-format code for a Managed Service for Apache Flink application.</p>
    pub fn zip_file_content(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.zip_file_content.as_ref()
    }
    /// <p>Information about the Amazon S3 bucket that contains the application code.</p>
    pub fn s3_content_location(&self) -> ::std::option::Option<&crate::types::S3ContentLocation> {
        self.s3_content_location.as_ref()
    }
}
impl CodeContent {
    /// Creates a new builder-style object to manufacture [`CodeContent`](crate::types::CodeContent).
    pub fn builder() -> crate::types::builders::CodeContentBuilder {
        crate::types::builders::CodeContentBuilder::default()
    }
}

/// A builder for [`CodeContent`](crate::types::CodeContent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodeContentBuilder {
    pub(crate) text_content: ::std::option::Option<::std::string::String>,
    pub(crate) zip_file_content: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) s3_content_location: ::std::option::Option<crate::types::S3ContentLocation>,
}
impl CodeContentBuilder {
    /// <p>The text-format code for a Managed Service for Apache Flink application.</p>
    pub fn text_content(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.text_content = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text-format code for a Managed Service for Apache Flink application.</p>
    pub fn set_text_content(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.text_content = input;
        self
    }
    /// <p>The text-format code for a Managed Service for Apache Flink application.</p>
    pub fn get_text_content(&self) -> &::std::option::Option<::std::string::String> {
        &self.text_content
    }
    /// <p>The zip-format code for a Managed Service for Apache Flink application.</p>
    pub fn zip_file_content(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.zip_file_content = ::std::option::Option::Some(input);
        self
    }
    /// <p>The zip-format code for a Managed Service for Apache Flink application.</p>
    pub fn set_zip_file_content(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.zip_file_content = input;
        self
    }
    /// <p>The zip-format code for a Managed Service for Apache Flink application.</p>
    pub fn get_zip_file_content(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.zip_file_content
    }
    /// <p>Information about the Amazon S3 bucket that contains the application code.</p>
    pub fn s3_content_location(mut self, input: crate::types::S3ContentLocation) -> Self {
        self.s3_content_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the Amazon S3 bucket that contains the application code.</p>
    pub fn set_s3_content_location(mut self, input: ::std::option::Option<crate::types::S3ContentLocation>) -> Self {
        self.s3_content_location = input;
        self
    }
    /// <p>Information about the Amazon S3 bucket that contains the application code.</p>
    pub fn get_s3_content_location(&self) -> &::std::option::Option<crate::types::S3ContentLocation> {
        &self.s3_content_location
    }
    /// Consumes the builder and constructs a [`CodeContent`](crate::types::CodeContent).
    pub fn build(self) -> crate::types::CodeContent {
        crate::types::CodeContent {
            text_content: self.text_content,
            zip_file_content: self.zip_file_content,
            s3_content_location: self.s3_content_location,
        }
    }
}
