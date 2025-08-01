// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a source file's formatting.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FileFormatDescriptor {
    /// <p>Contains information about how a source CSV data file should be analyzed.</p>
    pub csv_format_descriptor: ::std::option::Option<crate::types::CsvFormatDescriptor>,
    /// <p>Contains information about how a source JSON data file should be analyzed.</p>
    pub json_format_descriptor: ::std::option::Option<crate::types::JsonFormatDescriptor>,
}
impl FileFormatDescriptor {
    /// <p>Contains information about how a source CSV data file should be analyzed.</p>
    pub fn csv_format_descriptor(&self) -> ::std::option::Option<&crate::types::CsvFormatDescriptor> {
        self.csv_format_descriptor.as_ref()
    }
    /// <p>Contains information about how a source JSON data file should be analyzed.</p>
    pub fn json_format_descriptor(&self) -> ::std::option::Option<&crate::types::JsonFormatDescriptor> {
        self.json_format_descriptor.as_ref()
    }
}
impl FileFormatDescriptor {
    /// Creates a new builder-style object to manufacture [`FileFormatDescriptor`](crate::types::FileFormatDescriptor).
    pub fn builder() -> crate::types::builders::FileFormatDescriptorBuilder {
        crate::types::builders::FileFormatDescriptorBuilder::default()
    }
}

/// A builder for [`FileFormatDescriptor`](crate::types::FileFormatDescriptor).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FileFormatDescriptorBuilder {
    pub(crate) csv_format_descriptor: ::std::option::Option<crate::types::CsvFormatDescriptor>,
    pub(crate) json_format_descriptor: ::std::option::Option<crate::types::JsonFormatDescriptor>,
}
impl FileFormatDescriptorBuilder {
    /// <p>Contains information about how a source CSV data file should be analyzed.</p>
    pub fn csv_format_descriptor(mut self, input: crate::types::CsvFormatDescriptor) -> Self {
        self.csv_format_descriptor = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about how a source CSV data file should be analyzed.</p>
    pub fn set_csv_format_descriptor(mut self, input: ::std::option::Option<crate::types::CsvFormatDescriptor>) -> Self {
        self.csv_format_descriptor = input;
        self
    }
    /// <p>Contains information about how a source CSV data file should be analyzed.</p>
    pub fn get_csv_format_descriptor(&self) -> &::std::option::Option<crate::types::CsvFormatDescriptor> {
        &self.csv_format_descriptor
    }
    /// <p>Contains information about how a source JSON data file should be analyzed.</p>
    pub fn json_format_descriptor(mut self, input: crate::types::JsonFormatDescriptor) -> Self {
        self.json_format_descriptor = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about how a source JSON data file should be analyzed.</p>
    pub fn set_json_format_descriptor(mut self, input: ::std::option::Option<crate::types::JsonFormatDescriptor>) -> Self {
        self.json_format_descriptor = input;
        self
    }
    /// <p>Contains information about how a source JSON data file should be analyzed.</p>
    pub fn get_json_format_descriptor(&self) -> &::std::option::Option<crate::types::JsonFormatDescriptor> {
        &self.json_format_descriptor
    }
    /// Consumes the builder and constructs a [`FileFormatDescriptor`](crate::types::FileFormatDescriptor).
    pub fn build(self) -> crate::types::FileFormatDescriptor {
        crate::types::FileFormatDescriptor {
            csv_format_descriptor: self.csv_format_descriptor,
            json_format_descriptor: self.json_format_descriptor,
        }
    }
}
