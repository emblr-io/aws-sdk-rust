// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateDataRetentionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateDataRetentionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateDataRetentionOutput {
    /// Creates a new builder-style object to manufacture [`UpdateDataRetentionOutput`](crate::operation::update_data_retention::UpdateDataRetentionOutput).
    pub fn builder() -> crate::operation::update_data_retention::builders::UpdateDataRetentionOutputBuilder {
        crate::operation::update_data_retention::builders::UpdateDataRetentionOutputBuilder::default()
    }
}

/// A builder for [`UpdateDataRetentionOutput`](crate::operation::update_data_retention::UpdateDataRetentionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateDataRetentionOutputBuilder {
    _request_id: Option<String>,
}
impl UpdateDataRetentionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateDataRetentionOutput`](crate::operation::update_data_retention::UpdateDataRetentionOutput).
    pub fn build(self) -> crate::operation::update_data_retention::UpdateDataRetentionOutput {
        crate::operation::update_data_retention::UpdateDataRetentionOutput {
            _request_id: self._request_id,
        }
    }
}
