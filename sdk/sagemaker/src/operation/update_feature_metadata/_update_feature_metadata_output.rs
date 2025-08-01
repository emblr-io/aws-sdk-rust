// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFeatureMetadataOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateFeatureMetadataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateFeatureMetadataOutput {
    /// Creates a new builder-style object to manufacture [`UpdateFeatureMetadataOutput`](crate::operation::update_feature_metadata::UpdateFeatureMetadataOutput).
    pub fn builder() -> crate::operation::update_feature_metadata::builders::UpdateFeatureMetadataOutputBuilder {
        crate::operation::update_feature_metadata::builders::UpdateFeatureMetadataOutputBuilder::default()
    }
}

/// A builder for [`UpdateFeatureMetadataOutput`](crate::operation::update_feature_metadata::UpdateFeatureMetadataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFeatureMetadataOutputBuilder {
    _request_id: Option<String>,
}
impl UpdateFeatureMetadataOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateFeatureMetadataOutput`](crate::operation::update_feature_metadata::UpdateFeatureMetadataOutput).
    pub fn build(self) -> crate::operation::update_feature_metadata::UpdateFeatureMetadataOutput {
        crate::operation::update_feature_metadata::UpdateFeatureMetadataOutput {
            _request_id: self._request_id,
        }
    }
}
