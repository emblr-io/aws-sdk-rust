// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetImagePipelineOutput {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The image pipeline object.</p>
    pub image_pipeline: ::std::option::Option<crate::types::ImagePipeline>,
    _request_id: Option<String>,
}
impl GetImagePipelineOutput {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The image pipeline object.</p>
    pub fn image_pipeline(&self) -> ::std::option::Option<&crate::types::ImagePipeline> {
        self.image_pipeline.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetImagePipelineOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetImagePipelineOutput {
    /// Creates a new builder-style object to manufacture [`GetImagePipelineOutput`](crate::operation::get_image_pipeline::GetImagePipelineOutput).
    pub fn builder() -> crate::operation::get_image_pipeline::builders::GetImagePipelineOutputBuilder {
        crate::operation::get_image_pipeline::builders::GetImagePipelineOutputBuilder::default()
    }
}

/// A builder for [`GetImagePipelineOutput`](crate::operation::get_image_pipeline::GetImagePipelineOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetImagePipelineOutputBuilder {
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) image_pipeline: ::std::option::Option<crate::types::ImagePipeline>,
    _request_id: Option<String>,
}
impl GetImagePipelineOutputBuilder {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The image pipeline object.</p>
    pub fn image_pipeline(mut self, input: crate::types::ImagePipeline) -> Self {
        self.image_pipeline = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image pipeline object.</p>
    pub fn set_image_pipeline(mut self, input: ::std::option::Option<crate::types::ImagePipeline>) -> Self {
        self.image_pipeline = input;
        self
    }
    /// <p>The image pipeline object.</p>
    pub fn get_image_pipeline(&self) -> &::std::option::Option<crate::types::ImagePipeline> {
        &self.image_pipeline
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetImagePipelineOutput`](crate::operation::get_image_pipeline::GetImagePipelineOutput).
    pub fn build(self) -> crate::operation::get_image_pipeline::GetImagePipelineOutput {
        crate::operation::get_image_pipeline::GetImagePipelineOutput {
            request_id: self.request_id,
            image_pipeline: self.image_pipeline,
            _request_id: self._request_id,
        }
    }
}
