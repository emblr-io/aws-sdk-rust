// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the output of CopyImage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CopyImageOutput {
    /// <p>The ID of the new AMI.</p>
    pub image_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CopyImageOutput {
    /// <p>The ID of the new AMI.</p>
    pub fn image_id(&self) -> ::std::option::Option<&str> {
        self.image_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CopyImageOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CopyImageOutput {
    /// Creates a new builder-style object to manufacture [`CopyImageOutput`](crate::operation::copy_image::CopyImageOutput).
    pub fn builder() -> crate::operation::copy_image::builders::CopyImageOutputBuilder {
        crate::operation::copy_image::builders::CopyImageOutputBuilder::default()
    }
}

/// A builder for [`CopyImageOutput`](crate::operation::copy_image::CopyImageOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CopyImageOutputBuilder {
    pub(crate) image_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CopyImageOutputBuilder {
    /// <p>The ID of the new AMI.</p>
    pub fn image_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the new AMI.</p>
    pub fn set_image_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_id = input;
        self
    }
    /// <p>The ID of the new AMI.</p>
    pub fn get_image_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CopyImageOutput`](crate::operation::copy_image::CopyImageOutput).
    pub fn build(self) -> crate::operation::copy_image::CopyImageOutput {
        crate::operation::copy_image::CopyImageOutput {
            image_id: self.image_id,
            _request_id: self._request_id,
        }
    }
}
