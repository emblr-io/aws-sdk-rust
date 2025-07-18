// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Settings for customizing steps in the data source content ingestion pipeline.</p>
/// <p>You can configure the data source to process documents with a Lambda function after they are parsed and converted into chunks. When you add a post-chunking transformation, the service stores chunked documents in an S3 bucket and invokes a Lambda function to process them.</p>
/// <p>To process chunked documents with a Lambda function, define an S3 bucket path for input and output objects, and a transformation that specifies the Lambda function to invoke. You can use the Lambda function to customize how chunks are split, and the metadata for each chunk.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CustomTransformationConfiguration {
    /// <p>An S3 bucket path for input and output objects.</p>
    pub intermediate_storage: ::std::option::Option<crate::types::IntermediateStorage>,
    /// <p>A Lambda function that processes documents.</p>
    pub transformations: ::std::vec::Vec<crate::types::Transformation>,
}
impl CustomTransformationConfiguration {
    /// <p>An S3 bucket path for input and output objects.</p>
    pub fn intermediate_storage(&self) -> ::std::option::Option<&crate::types::IntermediateStorage> {
        self.intermediate_storage.as_ref()
    }
    /// <p>A Lambda function that processes documents.</p>
    pub fn transformations(&self) -> &[crate::types::Transformation] {
        use std::ops::Deref;
        self.transformations.deref()
    }
}
impl CustomTransformationConfiguration {
    /// Creates a new builder-style object to manufacture [`CustomTransformationConfiguration`](crate::types::CustomTransformationConfiguration).
    pub fn builder() -> crate::types::builders::CustomTransformationConfigurationBuilder {
        crate::types::builders::CustomTransformationConfigurationBuilder::default()
    }
}

/// A builder for [`CustomTransformationConfiguration`](crate::types::CustomTransformationConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CustomTransformationConfigurationBuilder {
    pub(crate) intermediate_storage: ::std::option::Option<crate::types::IntermediateStorage>,
    pub(crate) transformations: ::std::option::Option<::std::vec::Vec<crate::types::Transformation>>,
}
impl CustomTransformationConfigurationBuilder {
    /// <p>An S3 bucket path for input and output objects.</p>
    /// This field is required.
    pub fn intermediate_storage(mut self, input: crate::types::IntermediateStorage) -> Self {
        self.intermediate_storage = ::std::option::Option::Some(input);
        self
    }
    /// <p>An S3 bucket path for input and output objects.</p>
    pub fn set_intermediate_storage(mut self, input: ::std::option::Option<crate::types::IntermediateStorage>) -> Self {
        self.intermediate_storage = input;
        self
    }
    /// <p>An S3 bucket path for input and output objects.</p>
    pub fn get_intermediate_storage(&self) -> &::std::option::Option<crate::types::IntermediateStorage> {
        &self.intermediate_storage
    }
    /// Appends an item to `transformations`.
    ///
    /// To override the contents of this collection use [`set_transformations`](Self::set_transformations).
    ///
    /// <p>A Lambda function that processes documents.</p>
    pub fn transformations(mut self, input: crate::types::Transformation) -> Self {
        let mut v = self.transformations.unwrap_or_default();
        v.push(input);
        self.transformations = ::std::option::Option::Some(v);
        self
    }
    /// <p>A Lambda function that processes documents.</p>
    pub fn set_transformations(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Transformation>>) -> Self {
        self.transformations = input;
        self
    }
    /// <p>A Lambda function that processes documents.</p>
    pub fn get_transformations(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Transformation>> {
        &self.transformations
    }
    /// Consumes the builder and constructs a [`CustomTransformationConfiguration`](crate::types::CustomTransformationConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`transformations`](crate::types::builders::CustomTransformationConfigurationBuilder::transformations)
    pub fn build(self) -> ::std::result::Result<crate::types::CustomTransformationConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CustomTransformationConfiguration {
            intermediate_storage: self.intermediate_storage,
            transformations: self.transformations.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "transformations",
                    "transformations was not specified but it is required when building CustomTransformationConfiguration",
                )
            })?,
        })
    }
}
