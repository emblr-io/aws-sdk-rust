// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartMetricsExportOutput {
    /// <p>Identifier of the metrics export task.</p>
    pub metrics_export_id: ::std::string::String,
    /// <p>Indicates the status of the metrics export task.</p>
    pub status: crate::types::MetricsExportStatusType,
    _request_id: Option<String>,
}
impl StartMetricsExportOutput {
    /// <p>Identifier of the metrics export task.</p>
    pub fn metrics_export_id(&self) -> &str {
        use std::ops::Deref;
        self.metrics_export_id.deref()
    }
    /// <p>Indicates the status of the metrics export task.</p>
    pub fn status(&self) -> &crate::types::MetricsExportStatusType {
        &self.status
    }
}
impl ::aws_types::request_id::RequestId for StartMetricsExportOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartMetricsExportOutput {
    /// Creates a new builder-style object to manufacture [`StartMetricsExportOutput`](crate::operation::start_metrics_export::StartMetricsExportOutput).
    pub fn builder() -> crate::operation::start_metrics_export::builders::StartMetricsExportOutputBuilder {
        crate::operation::start_metrics_export::builders::StartMetricsExportOutputBuilder::default()
    }
}

/// A builder for [`StartMetricsExportOutput`](crate::operation::start_metrics_export::StartMetricsExportOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartMetricsExportOutputBuilder {
    pub(crate) metrics_export_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::MetricsExportStatusType>,
    _request_id: Option<String>,
}
impl StartMetricsExportOutputBuilder {
    /// <p>Identifier of the metrics export task.</p>
    /// This field is required.
    pub fn metrics_export_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metrics_export_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Identifier of the metrics export task.</p>
    pub fn set_metrics_export_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metrics_export_id = input;
        self
    }
    /// <p>Identifier of the metrics export task.</p>
    pub fn get_metrics_export_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.metrics_export_id
    }
    /// <p>Indicates the status of the metrics export task.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::MetricsExportStatusType) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the status of the metrics export task.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::MetricsExportStatusType>) -> Self {
        self.status = input;
        self
    }
    /// <p>Indicates the status of the metrics export task.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::MetricsExportStatusType> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartMetricsExportOutput`](crate::operation::start_metrics_export::StartMetricsExportOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`metrics_export_id`](crate::operation::start_metrics_export::builders::StartMetricsExportOutputBuilder::metrics_export_id)
    /// - [`status`](crate::operation::start_metrics_export::builders::StartMetricsExportOutputBuilder::status)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_metrics_export::StartMetricsExportOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_metrics_export::StartMetricsExportOutput {
            metrics_export_id: self.metrics_export_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "metrics_export_id",
                    "metrics_export_id was not specified but it is required when building StartMetricsExportOutput",
                )
            })?,
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building StartMetricsExportOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
