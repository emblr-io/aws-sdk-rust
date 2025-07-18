// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteMlInputChannelDataOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteMlInputChannelDataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteMlInputChannelDataOutput {
    /// Creates a new builder-style object to manufacture [`DeleteMlInputChannelDataOutput`](crate::operation::delete_ml_input_channel_data::DeleteMlInputChannelDataOutput).
    pub fn builder() -> crate::operation::delete_ml_input_channel_data::builders::DeleteMlInputChannelDataOutputBuilder {
        crate::operation::delete_ml_input_channel_data::builders::DeleteMlInputChannelDataOutputBuilder::default()
    }
}

/// A builder for [`DeleteMlInputChannelDataOutput`](crate::operation::delete_ml_input_channel_data::DeleteMlInputChannelDataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteMlInputChannelDataOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteMlInputChannelDataOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteMlInputChannelDataOutput`](crate::operation::delete_ml_input_channel_data::DeleteMlInputChannelDataOutput).
    pub fn build(self) -> crate::operation::delete_ml_input_channel_data::DeleteMlInputChannelDataOutput {
        crate::operation::delete_ml_input_channel_data::DeleteMlInputChannelDataOutput {
            _request_id: self._request_id,
        }
    }
}
