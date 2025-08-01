// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Output Format of Document
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DocumentOutputFormat {
    /// Text Format of Document Output
    pub text_format: ::std::option::Option<crate::types::DocumentOutputTextFormat>,
    /// Additional File Format of Document Output
    pub additional_file_format: ::std::option::Option<crate::types::DocumentOutputAdditionalFileFormat>,
}
impl DocumentOutputFormat {
    /// Text Format of Document Output
    pub fn text_format(&self) -> ::std::option::Option<&crate::types::DocumentOutputTextFormat> {
        self.text_format.as_ref()
    }
    /// Additional File Format of Document Output
    pub fn additional_file_format(&self) -> ::std::option::Option<&crate::types::DocumentOutputAdditionalFileFormat> {
        self.additional_file_format.as_ref()
    }
}
impl DocumentOutputFormat {
    /// Creates a new builder-style object to manufacture [`DocumentOutputFormat`](crate::types::DocumentOutputFormat).
    pub fn builder() -> crate::types::builders::DocumentOutputFormatBuilder {
        crate::types::builders::DocumentOutputFormatBuilder::default()
    }
}

/// A builder for [`DocumentOutputFormat`](crate::types::DocumentOutputFormat).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DocumentOutputFormatBuilder {
    pub(crate) text_format: ::std::option::Option<crate::types::DocumentOutputTextFormat>,
    pub(crate) additional_file_format: ::std::option::Option<crate::types::DocumentOutputAdditionalFileFormat>,
}
impl DocumentOutputFormatBuilder {
    /// Text Format of Document Output
    /// This field is required.
    pub fn text_format(mut self, input: crate::types::DocumentOutputTextFormat) -> Self {
        self.text_format = ::std::option::Option::Some(input);
        self
    }
    /// Text Format of Document Output
    pub fn set_text_format(mut self, input: ::std::option::Option<crate::types::DocumentOutputTextFormat>) -> Self {
        self.text_format = input;
        self
    }
    /// Text Format of Document Output
    pub fn get_text_format(&self) -> &::std::option::Option<crate::types::DocumentOutputTextFormat> {
        &self.text_format
    }
    /// Additional File Format of Document Output
    /// This field is required.
    pub fn additional_file_format(mut self, input: crate::types::DocumentOutputAdditionalFileFormat) -> Self {
        self.additional_file_format = ::std::option::Option::Some(input);
        self
    }
    /// Additional File Format of Document Output
    pub fn set_additional_file_format(mut self, input: ::std::option::Option<crate::types::DocumentOutputAdditionalFileFormat>) -> Self {
        self.additional_file_format = input;
        self
    }
    /// Additional File Format of Document Output
    pub fn get_additional_file_format(&self) -> &::std::option::Option<crate::types::DocumentOutputAdditionalFileFormat> {
        &self.additional_file_format
    }
    /// Consumes the builder and constructs a [`DocumentOutputFormat`](crate::types::DocumentOutputFormat).
    pub fn build(self) -> crate::types::DocumentOutputFormat {
        crate::types::DocumentOutputFormat {
            text_format: self.text_format,
            additional_file_format: self.additional_file_format,
        }
    }
}
