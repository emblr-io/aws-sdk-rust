// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the source where the association execution details are stored.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OutputSource {
    /// <p>The ID of the output source, for example the URL of an S3 bucket.</p>
    pub output_source_id: ::std::option::Option<::std::string::String>,
    /// <p>The type of source where the association execution details are stored, for example, Amazon S3.</p>
    pub output_source_type: ::std::option::Option<::std::string::String>,
}
impl OutputSource {
    /// <p>The ID of the output source, for example the URL of an S3 bucket.</p>
    pub fn output_source_id(&self) -> ::std::option::Option<&str> {
        self.output_source_id.as_deref()
    }
    /// <p>The type of source where the association execution details are stored, for example, Amazon S3.</p>
    pub fn output_source_type(&self) -> ::std::option::Option<&str> {
        self.output_source_type.as_deref()
    }
}
impl OutputSource {
    /// Creates a new builder-style object to manufacture [`OutputSource`](crate::types::OutputSource).
    pub fn builder() -> crate::types::builders::OutputSourceBuilder {
        crate::types::builders::OutputSourceBuilder::default()
    }
}

/// A builder for [`OutputSource`](crate::types::OutputSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OutputSourceBuilder {
    pub(crate) output_source_id: ::std::option::Option<::std::string::String>,
    pub(crate) output_source_type: ::std::option::Option<::std::string::String>,
}
impl OutputSourceBuilder {
    /// <p>The ID of the output source, for example the URL of an S3 bucket.</p>
    pub fn output_source_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output_source_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the output source, for example the URL of an S3 bucket.</p>
    pub fn set_output_source_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output_source_id = input;
        self
    }
    /// <p>The ID of the output source, for example the URL of an S3 bucket.</p>
    pub fn get_output_source_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.output_source_id
    }
    /// <p>The type of source where the association execution details are stored, for example, Amazon S3.</p>
    pub fn output_source_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output_source_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of source where the association execution details are stored, for example, Amazon S3.</p>
    pub fn set_output_source_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output_source_type = input;
        self
    }
    /// <p>The type of source where the association execution details are stored, for example, Amazon S3.</p>
    pub fn get_output_source_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.output_source_type
    }
    /// Consumes the builder and constructs a [`OutputSource`](crate::types::OutputSource).
    pub fn build(self) -> crate::types::OutputSource {
        crate::types::OutputSource {
            output_source_id: self.output_source_id,
            output_source_type: self.output_source_type,
        }
    }
}
