// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Amazon S3 location that temporarily stores your data while it processes. Your information won't be saved permanently.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IntermediateSourceConfiguration {
    /// <p>The Amazon S3 location (bucket and prefix). For example: <code>s3://provider_bucket/DOC-EXAMPLE-BUCKET</code></p>
    pub intermediate_s3_path: ::std::string::String,
}
impl IntermediateSourceConfiguration {
    /// <p>The Amazon S3 location (bucket and prefix). For example: <code>s3://provider_bucket/DOC-EXAMPLE-BUCKET</code></p>
    pub fn intermediate_s3_path(&self) -> &str {
        use std::ops::Deref;
        self.intermediate_s3_path.deref()
    }
}
impl IntermediateSourceConfiguration {
    /// Creates a new builder-style object to manufacture [`IntermediateSourceConfiguration`](crate::types::IntermediateSourceConfiguration).
    pub fn builder() -> crate::types::builders::IntermediateSourceConfigurationBuilder {
        crate::types::builders::IntermediateSourceConfigurationBuilder::default()
    }
}

/// A builder for [`IntermediateSourceConfiguration`](crate::types::IntermediateSourceConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IntermediateSourceConfigurationBuilder {
    pub(crate) intermediate_s3_path: ::std::option::Option<::std::string::String>,
}
impl IntermediateSourceConfigurationBuilder {
    /// <p>The Amazon S3 location (bucket and prefix). For example: <code>s3://provider_bucket/DOC-EXAMPLE-BUCKET</code></p>
    /// This field is required.
    pub fn intermediate_s3_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.intermediate_s3_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 location (bucket and prefix). For example: <code>s3://provider_bucket/DOC-EXAMPLE-BUCKET</code></p>
    pub fn set_intermediate_s3_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.intermediate_s3_path = input;
        self
    }
    /// <p>The Amazon S3 location (bucket and prefix). For example: <code>s3://provider_bucket/DOC-EXAMPLE-BUCKET</code></p>
    pub fn get_intermediate_s3_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.intermediate_s3_path
    }
    /// Consumes the builder and constructs a [`IntermediateSourceConfiguration`](crate::types::IntermediateSourceConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`intermediate_s3_path`](crate::types::builders::IntermediateSourceConfigurationBuilder::intermediate_s3_path)
    pub fn build(self) -> ::std::result::Result<crate::types::IntermediateSourceConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IntermediateSourceConfiguration {
            intermediate_s3_path: self.intermediate_s3_path.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "intermediate_s3_path",
                    "intermediate_s3_path was not specified but it is required when building IntermediateSourceConfiguration",
                )
            })?,
        })
    }
}
