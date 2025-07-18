// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Metrics for the stream.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConverseStreamMetrics {
    /// <p>The latency for the streaming request, in milliseconds.</p>
    pub latency_ms: i64,
}
impl ConverseStreamMetrics {
    /// <p>The latency for the streaming request, in milliseconds.</p>
    pub fn latency_ms(&self) -> i64 {
        self.latency_ms
    }
}
impl ConverseStreamMetrics {
    /// Creates a new builder-style object to manufacture [`ConverseStreamMetrics`](crate::types::ConverseStreamMetrics).
    pub fn builder() -> crate::types::builders::ConverseStreamMetricsBuilder {
        crate::types::builders::ConverseStreamMetricsBuilder::default()
    }
}

/// A builder for [`ConverseStreamMetrics`](crate::types::ConverseStreamMetrics).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConverseStreamMetricsBuilder {
    pub(crate) latency_ms: ::std::option::Option<i64>,
}
impl ConverseStreamMetricsBuilder {
    /// <p>The latency for the streaming request, in milliseconds.</p>
    /// This field is required.
    pub fn latency_ms(mut self, input: i64) -> Self {
        self.latency_ms = ::std::option::Option::Some(input);
        self
    }
    /// <p>The latency for the streaming request, in milliseconds.</p>
    pub fn set_latency_ms(mut self, input: ::std::option::Option<i64>) -> Self {
        self.latency_ms = input;
        self
    }
    /// <p>The latency for the streaming request, in milliseconds.</p>
    pub fn get_latency_ms(&self) -> &::std::option::Option<i64> {
        &self.latency_ms
    }
    /// Consumes the builder and constructs a [`ConverseStreamMetrics`](crate::types::ConverseStreamMetrics).
    /// This method will fail if any of the following fields are not set:
    /// - [`latency_ms`](crate::types::builders::ConverseStreamMetricsBuilder::latency_ms)
    pub fn build(self) -> ::std::result::Result<crate::types::ConverseStreamMetrics, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ConverseStreamMetrics {
            latency_ms: self.latency_ms.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "latency_ms",
                    "latency_ms was not specified but it is required when building ConverseStreamMetrics",
                )
            })?,
        })
    }
}
