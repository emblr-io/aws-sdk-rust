// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateTimeSeriesFromAssetPropertyOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DisassociateTimeSeriesFromAssetPropertyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DisassociateTimeSeriesFromAssetPropertyOutput {
    /// Creates a new builder-style object to manufacture [`DisassociateTimeSeriesFromAssetPropertyOutput`](crate::operation::disassociate_time_series_from_asset_property::DisassociateTimeSeriesFromAssetPropertyOutput).
    pub fn builder() -> crate::operation::disassociate_time_series_from_asset_property::builders::DisassociateTimeSeriesFromAssetPropertyOutputBuilder
    {
        crate::operation::disassociate_time_series_from_asset_property::builders::DisassociateTimeSeriesFromAssetPropertyOutputBuilder::default()
    }
}

/// A builder for [`DisassociateTimeSeriesFromAssetPropertyOutput`](crate::operation::disassociate_time_series_from_asset_property::DisassociateTimeSeriesFromAssetPropertyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateTimeSeriesFromAssetPropertyOutputBuilder {
    _request_id: Option<String>,
}
impl DisassociateTimeSeriesFromAssetPropertyOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DisassociateTimeSeriesFromAssetPropertyOutput`](crate::operation::disassociate_time_series_from_asset_property::DisassociateTimeSeriesFromAssetPropertyOutput).
    pub fn build(self) -> crate::operation::disassociate_time_series_from_asset_property::DisassociateTimeSeriesFromAssetPropertyOutput {
        crate::operation::disassociate_time_series_from_asset_property::DisassociateTimeSeriesFromAssetPropertyOutput {
            _request_id: self._request_id,
        }
    }
}
