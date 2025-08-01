// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The data sink of the configuration object.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConcatenationSink {
    /// <p>The type of data sink in the configuration object.</p>
    pub r#type: crate::types::ConcatenationSinkType,
    /// <p>The configuration settings for an Amazon S3 bucket sink.</p>
    pub s3_bucket_sink_configuration: ::std::option::Option<crate::types::S3BucketSinkConfiguration>,
}
impl ConcatenationSink {
    /// <p>The type of data sink in the configuration object.</p>
    pub fn r#type(&self) -> &crate::types::ConcatenationSinkType {
        &self.r#type
    }
    /// <p>The configuration settings for an Amazon S3 bucket sink.</p>
    pub fn s3_bucket_sink_configuration(&self) -> ::std::option::Option<&crate::types::S3BucketSinkConfiguration> {
        self.s3_bucket_sink_configuration.as_ref()
    }
}
impl ConcatenationSink {
    /// Creates a new builder-style object to manufacture [`ConcatenationSink`](crate::types::ConcatenationSink).
    pub fn builder() -> crate::types::builders::ConcatenationSinkBuilder {
        crate::types::builders::ConcatenationSinkBuilder::default()
    }
}

/// A builder for [`ConcatenationSink`](crate::types::ConcatenationSink).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConcatenationSinkBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::ConcatenationSinkType>,
    pub(crate) s3_bucket_sink_configuration: ::std::option::Option<crate::types::S3BucketSinkConfiguration>,
}
impl ConcatenationSinkBuilder {
    /// <p>The type of data sink in the configuration object.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ConcatenationSinkType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of data sink in the configuration object.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ConcatenationSinkType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of data sink in the configuration object.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ConcatenationSinkType> {
        &self.r#type
    }
    /// <p>The configuration settings for an Amazon S3 bucket sink.</p>
    /// This field is required.
    pub fn s3_bucket_sink_configuration(mut self, input: crate::types::S3BucketSinkConfiguration) -> Self {
        self.s3_bucket_sink_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration settings for an Amazon S3 bucket sink.</p>
    pub fn set_s3_bucket_sink_configuration(mut self, input: ::std::option::Option<crate::types::S3BucketSinkConfiguration>) -> Self {
        self.s3_bucket_sink_configuration = input;
        self
    }
    /// <p>The configuration settings for an Amazon S3 bucket sink.</p>
    pub fn get_s3_bucket_sink_configuration(&self) -> &::std::option::Option<crate::types::S3BucketSinkConfiguration> {
        &self.s3_bucket_sink_configuration
    }
    /// Consumes the builder and constructs a [`ConcatenationSink`](crate::types::ConcatenationSink).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::ConcatenationSinkBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::ConcatenationSink, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConcatenationSink {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building ConcatenationSink",
                )
            })?,
            s3_bucket_sink_configuration: self.s3_bucket_sink_configuration,
        })
    }
}
