// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPropertygraphStatisticsOutput {
    /// <p>The HTTP return code of the request. If the request succeeded, the code is 200. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/neptune-dfe-statistics.html#neptune-dfe-statistics-errors">Common error codes for DFE statistics request</a> for a list of common errors.</p>
    pub status: ::std::string::String,
    /// <p>Statistics for property-graph data.</p>
    pub payload: ::std::option::Option<crate::types::Statistics>,
    _request_id: Option<String>,
}
impl GetPropertygraphStatisticsOutput {
    /// <p>The HTTP return code of the request. If the request succeeded, the code is 200. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/neptune-dfe-statistics.html#neptune-dfe-statistics-errors">Common error codes for DFE statistics request</a> for a list of common errors.</p>
    pub fn status(&self) -> &str {
        use std::ops::Deref;
        self.status.deref()
    }
    /// <p>Statistics for property-graph data.</p>
    pub fn payload(&self) -> ::std::option::Option<&crate::types::Statistics> {
        self.payload.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetPropertygraphStatisticsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetPropertygraphStatisticsOutput {
    /// Creates a new builder-style object to manufacture [`GetPropertygraphStatisticsOutput`](crate::operation::get_propertygraph_statistics::GetPropertygraphStatisticsOutput).
    pub fn builder() -> crate::operation::get_propertygraph_statistics::builders::GetPropertygraphStatisticsOutputBuilder {
        crate::operation::get_propertygraph_statistics::builders::GetPropertygraphStatisticsOutputBuilder::default()
    }
}

/// A builder for [`GetPropertygraphStatisticsOutput`](crate::operation::get_propertygraph_statistics::GetPropertygraphStatisticsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPropertygraphStatisticsOutputBuilder {
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) payload: ::std::option::Option<crate::types::Statistics>,
    _request_id: Option<String>,
}
impl GetPropertygraphStatisticsOutputBuilder {
    /// <p>The HTTP return code of the request. If the request succeeded, the code is 200. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/neptune-dfe-statistics.html#neptune-dfe-statistics-errors">Common error codes for DFE statistics request</a> for a list of common errors.</p>
    /// This field is required.
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The HTTP return code of the request. If the request succeeded, the code is 200. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/neptune-dfe-statistics.html#neptune-dfe-statistics-errors">Common error codes for DFE statistics request</a> for a list of common errors.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The HTTP return code of the request. If the request succeeded, the code is 200. See <a href="https://docs.aws.amazon.com/neptune/latest/userguide/neptune-dfe-statistics.html#neptune-dfe-statistics-errors">Common error codes for DFE statistics request</a> for a list of common errors.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>Statistics for property-graph data.</p>
    /// This field is required.
    pub fn payload(mut self, input: crate::types::Statistics) -> Self {
        self.payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>Statistics for property-graph data.</p>
    pub fn set_payload(mut self, input: ::std::option::Option<crate::types::Statistics>) -> Self {
        self.payload = input;
        self
    }
    /// <p>Statistics for property-graph data.</p>
    pub fn get_payload(&self) -> &::std::option::Option<crate::types::Statistics> {
        &self.payload
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetPropertygraphStatisticsOutput`](crate::operation::get_propertygraph_statistics::GetPropertygraphStatisticsOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`status`](crate::operation::get_propertygraph_statistics::builders::GetPropertygraphStatisticsOutputBuilder::status)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_propertygraph_statistics::GetPropertygraphStatisticsOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_propertygraph_statistics::GetPropertygraphStatisticsOutput {
            status: self.status.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "status",
                    "status was not specified but it is required when building GetPropertygraphStatisticsOutput",
                )
            })?,
            payload: self.payload,
            _request_id: self._request_id,
        })
    }
}
