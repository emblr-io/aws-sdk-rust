// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetImageOutput {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The image object.</p>
    pub image: ::std::option::Option<crate::types::Image>,
    _request_id: Option<String>,
}
impl GetImageOutput {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The image object.</p>
    pub fn image(&self) -> ::std::option::Option<&crate::types::Image> {
        self.image.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetImageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetImageOutput {
    /// Creates a new builder-style object to manufacture [`GetImageOutput`](crate::operation::get_image::GetImageOutput).
    pub fn builder() -> crate::operation::get_image::builders::GetImageOutputBuilder {
        crate::operation::get_image::builders::GetImageOutputBuilder::default()
    }
}

/// A builder for [`GetImageOutput`](crate::operation::get_image::GetImageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetImageOutputBuilder {
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) image: ::std::option::Option<crate::types::Image>,
    _request_id: Option<String>,
}
impl GetImageOutputBuilder {
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
    /// <p>The image object.</p>
    pub fn image(mut self, input: crate::types::Image) -> Self {
        self.image = ::std::option::Option::Some(input);
        self
    }
    /// <p>The image object.</p>
    pub fn set_image(mut self, input: ::std::option::Option<crate::types::Image>) -> Self {
        self.image = input;
        self
    }
    /// <p>The image object.</p>
    pub fn get_image(&self) -> &::std::option::Option<crate::types::Image> {
        &self.image
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetImageOutput`](crate::operation::get_image::GetImageOutput).
    pub fn build(self) -> crate::operation::get_image::GetImageOutput {
        crate::operation::get_image::GetImageOutput {
            request_id: self.request_id,
            image: self.image,
            _request_id: self._request_id,
        }
    }
}
