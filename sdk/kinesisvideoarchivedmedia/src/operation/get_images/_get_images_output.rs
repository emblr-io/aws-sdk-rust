// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetImagesOutput {
    /// <p>The list of images generated from the video stream. If there is no media available for the given timestamp, the <code>NO_MEDIA</code> error will be listed in the output. If an error occurs while the image is being generated, the <code>MEDIA_ERROR</code> will be listed in the output as the cause of the missing image.</p>
    pub images: ::std::option::Option<::std::vec::Vec<crate::types::Image>>,
    /// <p>The encrypted token that was used in the request to get more images.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetImagesOutput {
    /// <p>The list of images generated from the video stream. If there is no media available for the given timestamp, the <code>NO_MEDIA</code> error will be listed in the output. If an error occurs while the image is being generated, the <code>MEDIA_ERROR</code> will be listed in the output as the cause of the missing image.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.images.is_none()`.
    pub fn images(&self) -> &[crate::types::Image] {
        self.images.as_deref().unwrap_or_default()
    }
    /// <p>The encrypted token that was used in the request to get more images.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetImagesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetImagesOutput {
    /// Creates a new builder-style object to manufacture [`GetImagesOutput`](crate::operation::get_images::GetImagesOutput).
    pub fn builder() -> crate::operation::get_images::builders::GetImagesOutputBuilder {
        crate::operation::get_images::builders::GetImagesOutputBuilder::default()
    }
}

/// A builder for [`GetImagesOutput`](crate::operation::get_images::GetImagesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetImagesOutputBuilder {
    pub(crate) images: ::std::option::Option<::std::vec::Vec<crate::types::Image>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetImagesOutputBuilder {
    /// Appends an item to `images`.
    ///
    /// To override the contents of this collection use [`set_images`](Self::set_images).
    ///
    /// <p>The list of images generated from the video stream. If there is no media available for the given timestamp, the <code>NO_MEDIA</code> error will be listed in the output. If an error occurs while the image is being generated, the <code>MEDIA_ERROR</code> will be listed in the output as the cause of the missing image.</p>
    pub fn images(mut self, input: crate::types::Image) -> Self {
        let mut v = self.images.unwrap_or_default();
        v.push(input);
        self.images = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of images generated from the video stream. If there is no media available for the given timestamp, the <code>NO_MEDIA</code> error will be listed in the output. If an error occurs while the image is being generated, the <code>MEDIA_ERROR</code> will be listed in the output as the cause of the missing image.</p>
    pub fn set_images(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Image>>) -> Self {
        self.images = input;
        self
    }
    /// <p>The list of images generated from the video stream. If there is no media available for the given timestamp, the <code>NO_MEDIA</code> error will be listed in the output. If an error occurs while the image is being generated, the <code>MEDIA_ERROR</code> will be listed in the output as the cause of the missing image.</p>
    pub fn get_images(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Image>> {
        &self.images
    }
    /// <p>The encrypted token that was used in the request to get more images.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The encrypted token that was used in the request to get more images.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The encrypted token that was used in the request to get more images.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetImagesOutput`](crate::operation::get_images::GetImagesOutput).
    pub fn build(self) -> crate::operation::get_images::GetImagesOutput {
        crate::operation::get_images::GetImagesOutput {
            images: self.images,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
