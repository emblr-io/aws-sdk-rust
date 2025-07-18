// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configuration specifying how to treat different headers. If no headers are specified Amazon SageMaker AI will by default base64 encode when capturing the data.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CaptureContentTypeHeader {
    /// <p>The list of all content type headers that Amazon SageMaker AI will treat as CSV and capture accordingly.</p>
    pub csv_content_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The list of all content type headers that SageMaker AI will treat as JSON and capture accordingly.</p>
    pub json_content_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CaptureContentTypeHeader {
    /// <p>The list of all content type headers that Amazon SageMaker AI will treat as CSV and capture accordingly.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.csv_content_types.is_none()`.
    pub fn csv_content_types(&self) -> &[::std::string::String] {
        self.csv_content_types.as_deref().unwrap_or_default()
    }
    /// <p>The list of all content type headers that SageMaker AI will treat as JSON and capture accordingly.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.json_content_types.is_none()`.
    pub fn json_content_types(&self) -> &[::std::string::String] {
        self.json_content_types.as_deref().unwrap_or_default()
    }
}
impl CaptureContentTypeHeader {
    /// Creates a new builder-style object to manufacture [`CaptureContentTypeHeader`](crate::types::CaptureContentTypeHeader).
    pub fn builder() -> crate::types::builders::CaptureContentTypeHeaderBuilder {
        crate::types::builders::CaptureContentTypeHeaderBuilder::default()
    }
}

/// A builder for [`CaptureContentTypeHeader`](crate::types::CaptureContentTypeHeader).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CaptureContentTypeHeaderBuilder {
    pub(crate) csv_content_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) json_content_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl CaptureContentTypeHeaderBuilder {
    /// Appends an item to `csv_content_types`.
    ///
    /// To override the contents of this collection use [`set_csv_content_types`](Self::set_csv_content_types).
    ///
    /// <p>The list of all content type headers that Amazon SageMaker AI will treat as CSV and capture accordingly.</p>
    pub fn csv_content_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.csv_content_types.unwrap_or_default();
        v.push(input.into());
        self.csv_content_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of all content type headers that Amazon SageMaker AI will treat as CSV and capture accordingly.</p>
    pub fn set_csv_content_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.csv_content_types = input;
        self
    }
    /// <p>The list of all content type headers that Amazon SageMaker AI will treat as CSV and capture accordingly.</p>
    pub fn get_csv_content_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.csv_content_types
    }
    /// Appends an item to `json_content_types`.
    ///
    /// To override the contents of this collection use [`set_json_content_types`](Self::set_json_content_types).
    ///
    /// <p>The list of all content type headers that SageMaker AI will treat as JSON and capture accordingly.</p>
    pub fn json_content_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.json_content_types.unwrap_or_default();
        v.push(input.into());
        self.json_content_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of all content type headers that SageMaker AI will treat as JSON and capture accordingly.</p>
    pub fn set_json_content_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.json_content_types = input;
        self
    }
    /// <p>The list of all content type headers that SageMaker AI will treat as JSON and capture accordingly.</p>
    pub fn get_json_content_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.json_content_types
    }
    /// Consumes the builder and constructs a [`CaptureContentTypeHeader`](crate::types::CaptureContentTypeHeader).
    pub fn build(self) -> crate::types::CaptureContentTypeHeader {
        crate::types::CaptureContentTypeHeader {
            csv_content_types: self.csv_content_types,
            json_content_types: self.json_content_types,
        }
    }
}
