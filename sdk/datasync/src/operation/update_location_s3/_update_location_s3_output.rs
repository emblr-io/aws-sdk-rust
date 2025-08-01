// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLocationS3Output {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateLocationS3Output {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateLocationS3Output {
    /// Creates a new builder-style object to manufacture [`UpdateLocationS3Output`](crate::operation::update_location_s3::UpdateLocationS3Output).
    pub fn builder() -> crate::operation::update_location_s3::builders::UpdateLocationS3OutputBuilder {
        crate::operation::update_location_s3::builders::UpdateLocationS3OutputBuilder::default()
    }
}

/// A builder for [`UpdateLocationS3Output`](crate::operation::update_location_s3::UpdateLocationS3Output).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLocationS3OutputBuilder {
    _request_id: Option<String>,
}
impl UpdateLocationS3OutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateLocationS3Output`](crate::operation::update_location_s3::UpdateLocationS3Output).
    pub fn build(self) -> crate::operation::update_location_s3::UpdateLocationS3Output {
        crate::operation::update_location_s3::UpdateLocationS3Output {
            _request_id: self._request_id,
        }
    }
}
