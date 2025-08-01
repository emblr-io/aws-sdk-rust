// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutTelemetryRecordsOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutTelemetryRecordsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutTelemetryRecordsOutput {
    /// Creates a new builder-style object to manufacture [`PutTelemetryRecordsOutput`](crate::operation::put_telemetry_records::PutTelemetryRecordsOutput).
    pub fn builder() -> crate::operation::put_telemetry_records::builders::PutTelemetryRecordsOutputBuilder {
        crate::operation::put_telemetry_records::builders::PutTelemetryRecordsOutputBuilder::default()
    }
}

/// A builder for [`PutTelemetryRecordsOutput`](crate::operation::put_telemetry_records::PutTelemetryRecordsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutTelemetryRecordsOutputBuilder {
    _request_id: Option<String>,
}
impl PutTelemetryRecordsOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutTelemetryRecordsOutput`](crate::operation::put_telemetry_records::PutTelemetryRecordsOutput).
    pub fn build(self) -> crate::operation::put_telemetry_records::PutTelemetryRecordsOutput {
        crate::operation::put_telemetry_records::PutTelemetryRecordsOutput {
            _request_id: self._request_id,
        }
    }
}
