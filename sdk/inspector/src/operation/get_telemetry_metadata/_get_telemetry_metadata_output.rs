// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTelemetryMetadataOutput {
    /// <p>Telemetry details.</p>
    pub telemetry_metadata: ::std::vec::Vec<crate::types::TelemetryMetadata>,
    _request_id: Option<String>,
}
impl GetTelemetryMetadataOutput {
    /// <p>Telemetry details.</p>
    pub fn telemetry_metadata(&self) -> &[crate::types::TelemetryMetadata] {
        use std::ops::Deref;
        self.telemetry_metadata.deref()
    }
}
impl ::aws_types::request_id::RequestId for GetTelemetryMetadataOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTelemetryMetadataOutput {
    /// Creates a new builder-style object to manufacture [`GetTelemetryMetadataOutput`](crate::operation::get_telemetry_metadata::GetTelemetryMetadataOutput).
    pub fn builder() -> crate::operation::get_telemetry_metadata::builders::GetTelemetryMetadataOutputBuilder {
        crate::operation::get_telemetry_metadata::builders::GetTelemetryMetadataOutputBuilder::default()
    }
}

/// A builder for [`GetTelemetryMetadataOutput`](crate::operation::get_telemetry_metadata::GetTelemetryMetadataOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTelemetryMetadataOutputBuilder {
    pub(crate) telemetry_metadata: ::std::option::Option<::std::vec::Vec<crate::types::TelemetryMetadata>>,
    _request_id: Option<String>,
}
impl GetTelemetryMetadataOutputBuilder {
    /// Appends an item to `telemetry_metadata`.
    ///
    /// To override the contents of this collection use [`set_telemetry_metadata`](Self::set_telemetry_metadata).
    ///
    /// <p>Telemetry details.</p>
    pub fn telemetry_metadata(mut self, input: crate::types::TelemetryMetadata) -> Self {
        let mut v = self.telemetry_metadata.unwrap_or_default();
        v.push(input);
        self.telemetry_metadata = ::std::option::Option::Some(v);
        self
    }
    /// <p>Telemetry details.</p>
    pub fn set_telemetry_metadata(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TelemetryMetadata>>) -> Self {
        self.telemetry_metadata = input;
        self
    }
    /// <p>Telemetry details.</p>
    pub fn get_telemetry_metadata(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TelemetryMetadata>> {
        &self.telemetry_metadata
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTelemetryMetadataOutput`](crate::operation::get_telemetry_metadata::GetTelemetryMetadataOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`telemetry_metadata`](crate::operation::get_telemetry_metadata::builders::GetTelemetryMetadataOutputBuilder::telemetry_metadata)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_telemetry_metadata::GetTelemetryMetadataOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_telemetry_metadata::GetTelemetryMetadataOutput {
            telemetry_metadata: self.telemetry_metadata.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "telemetry_metadata",
                    "telemetry_metadata was not specified but it is required when building GetTelemetryMetadataOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
