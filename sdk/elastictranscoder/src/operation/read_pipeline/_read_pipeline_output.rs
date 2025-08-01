// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The <code>ReadPipelineResponse</code> structure.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReadPipelineOutput {
    /// <p>A section of the response body that provides information about the pipeline.</p>
    pub pipeline: ::std::option::Option<crate::types::Pipeline>,
    /// <p>Elastic Transcoder returns a warning if the resources used by your pipeline are not in the same region as the pipeline.</p>
    /// <p>Using resources in the same region, such as your Amazon S3 buckets, Amazon SNS notification topics, and AWS KMS key, reduces processing time and prevents cross-regional charges.</p>
    pub warnings: ::std::option::Option<::std::vec::Vec<crate::types::Warning>>,
    _request_id: Option<String>,
}
impl ReadPipelineOutput {
    /// <p>A section of the response body that provides information about the pipeline.</p>
    pub fn pipeline(&self) -> ::std::option::Option<&crate::types::Pipeline> {
        self.pipeline.as_ref()
    }
    /// <p>Elastic Transcoder returns a warning if the resources used by your pipeline are not in the same region as the pipeline.</p>
    /// <p>Using resources in the same region, such as your Amazon S3 buckets, Amazon SNS notification topics, and AWS KMS key, reduces processing time and prevents cross-regional charges.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.warnings.is_none()`.
    pub fn warnings(&self) -> &[crate::types::Warning] {
        self.warnings.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for ReadPipelineOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ReadPipelineOutput {
    /// Creates a new builder-style object to manufacture [`ReadPipelineOutput`](crate::operation::read_pipeline::ReadPipelineOutput).
    pub fn builder() -> crate::operation::read_pipeline::builders::ReadPipelineOutputBuilder {
        crate::operation::read_pipeline::builders::ReadPipelineOutputBuilder::default()
    }
}

/// A builder for [`ReadPipelineOutput`](crate::operation::read_pipeline::ReadPipelineOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReadPipelineOutputBuilder {
    pub(crate) pipeline: ::std::option::Option<crate::types::Pipeline>,
    pub(crate) warnings: ::std::option::Option<::std::vec::Vec<crate::types::Warning>>,
    _request_id: Option<String>,
}
impl ReadPipelineOutputBuilder {
    /// <p>A section of the response body that provides information about the pipeline.</p>
    pub fn pipeline(mut self, input: crate::types::Pipeline) -> Self {
        self.pipeline = ::std::option::Option::Some(input);
        self
    }
    /// <p>A section of the response body that provides information about the pipeline.</p>
    pub fn set_pipeline(mut self, input: ::std::option::Option<crate::types::Pipeline>) -> Self {
        self.pipeline = input;
        self
    }
    /// <p>A section of the response body that provides information about the pipeline.</p>
    pub fn get_pipeline(&self) -> &::std::option::Option<crate::types::Pipeline> {
        &self.pipeline
    }
    /// Appends an item to `warnings`.
    ///
    /// To override the contents of this collection use [`set_warnings`](Self::set_warnings).
    ///
    /// <p>Elastic Transcoder returns a warning if the resources used by your pipeline are not in the same region as the pipeline.</p>
    /// <p>Using resources in the same region, such as your Amazon S3 buckets, Amazon SNS notification topics, and AWS KMS key, reduces processing time and prevents cross-regional charges.</p>
    pub fn warnings(mut self, input: crate::types::Warning) -> Self {
        let mut v = self.warnings.unwrap_or_default();
        v.push(input);
        self.warnings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Elastic Transcoder returns a warning if the resources used by your pipeline are not in the same region as the pipeline.</p>
    /// <p>Using resources in the same region, such as your Amazon S3 buckets, Amazon SNS notification topics, and AWS KMS key, reduces processing time and prevents cross-regional charges.</p>
    pub fn set_warnings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Warning>>) -> Self {
        self.warnings = input;
        self
    }
    /// <p>Elastic Transcoder returns a warning if the resources used by your pipeline are not in the same region as the pipeline.</p>
    /// <p>Using resources in the same region, such as your Amazon S3 buckets, Amazon SNS notification topics, and AWS KMS key, reduces processing time and prevents cross-regional charges.</p>
    pub fn get_warnings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Warning>> {
        &self.warnings
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ReadPipelineOutput`](crate::operation::read_pipeline::ReadPipelineOutput).
    pub fn build(self) -> crate::operation::read_pipeline::ReadPipelineOutput {
        crate::operation::read_pipeline::ReadPipelineOutput {
            pipeline: self.pipeline,
            warnings: self.warnings,
            _request_id: self._request_id,
        }
    }
}
