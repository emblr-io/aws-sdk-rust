// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetSampleDataInput {
    /// <p>A datasource bucket in Amazon S3.</p>
    pub s3_source_config: ::std::option::Option<crate::types::SampleDataS3SourceConfig>,
}
impl GetSampleDataInput {
    /// <p>A datasource bucket in Amazon S3.</p>
    pub fn s3_source_config(&self) -> ::std::option::Option<&crate::types::SampleDataS3SourceConfig> {
        self.s3_source_config.as_ref()
    }
}
impl GetSampleDataInput {
    /// Creates a new builder-style object to manufacture [`GetSampleDataInput`](crate::operation::get_sample_data::GetSampleDataInput).
    pub fn builder() -> crate::operation::get_sample_data::builders::GetSampleDataInputBuilder {
        crate::operation::get_sample_data::builders::GetSampleDataInputBuilder::default()
    }
}

/// A builder for [`GetSampleDataInput`](crate::operation::get_sample_data::GetSampleDataInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetSampleDataInputBuilder {
    pub(crate) s3_source_config: ::std::option::Option<crate::types::SampleDataS3SourceConfig>,
}
impl GetSampleDataInputBuilder {
    /// <p>A datasource bucket in Amazon S3.</p>
    pub fn s3_source_config(mut self, input: crate::types::SampleDataS3SourceConfig) -> Self {
        self.s3_source_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>A datasource bucket in Amazon S3.</p>
    pub fn set_s3_source_config(mut self, input: ::std::option::Option<crate::types::SampleDataS3SourceConfig>) -> Self {
        self.s3_source_config = input;
        self
    }
    /// <p>A datasource bucket in Amazon S3.</p>
    pub fn get_s3_source_config(&self) -> &::std::option::Option<crate::types::SampleDataS3SourceConfig> {
        &self.s3_source_config
    }
    /// Consumes the builder and constructs a [`GetSampleDataInput`](crate::operation::get_sample_data::GetSampleDataInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_sample_data::GetSampleDataInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_sample_data::GetSampleDataInput {
            s3_source_config: self.s3_source_config,
        })
    }
}
