// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConverseOutput {
    /// <p>The result from the call to <code>Converse</code>.</p>
    pub output: ::std::option::Option<crate::types::ConverseOutput>,
    /// <p>The reason why the model stopped generating output.</p>
    pub stop_reason: crate::types::StopReason,
    /// <p>The total number of tokens used in the call to <code>Converse</code>. The total includes the tokens input to the model and the tokens generated by the model.</p>
    pub usage: ::std::option::Option<crate::types::TokenUsage>,
    /// <p>Metrics for the call to <code>Converse</code>.</p>
    pub metrics: ::std::option::Option<crate::types::ConverseMetrics>,
    /// <p>Additional fields in the response that are unique to the model.</p>
    pub additional_model_response_fields: ::std::option::Option<::aws_smithy_types::Document>,
    /// <p>A trace object that contains information about the Guardrail behavior.</p>
    pub trace: ::std::option::Option<crate::types::ConverseTrace>,
    /// <p>Model performance settings for the request.</p>
    pub performance_config: ::std::option::Option<crate::types::PerformanceConfiguration>,
    _request_id: Option<String>,
}
impl ConverseOutput {
    /// <p>The result from the call to <code>Converse</code>.</p>
    pub fn output(&self) -> ::std::option::Option<&crate::types::ConverseOutput> {
        self.output.as_ref()
    }
    /// <p>The reason why the model stopped generating output.</p>
    pub fn stop_reason(&self) -> &crate::types::StopReason {
        &self.stop_reason
    }
    /// <p>The total number of tokens used in the call to <code>Converse</code>. The total includes the tokens input to the model and the tokens generated by the model.</p>
    pub fn usage(&self) -> ::std::option::Option<&crate::types::TokenUsage> {
        self.usage.as_ref()
    }
    /// <p>Metrics for the call to <code>Converse</code>.</p>
    pub fn metrics(&self) -> ::std::option::Option<&crate::types::ConverseMetrics> {
        self.metrics.as_ref()
    }
    /// <p>Additional fields in the response that are unique to the model.</p>
    pub fn additional_model_response_fields(&self) -> ::std::option::Option<&::aws_smithy_types::Document> {
        self.additional_model_response_fields.as_ref()
    }
    /// <p>A trace object that contains information about the Guardrail behavior.</p>
    pub fn trace(&self) -> ::std::option::Option<&crate::types::ConverseTrace> {
        self.trace.as_ref()
    }
    /// <p>Model performance settings for the request.</p>
    pub fn performance_config(&self) -> ::std::option::Option<&crate::types::PerformanceConfiguration> {
        self.performance_config.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for ConverseOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ConverseOutput {
    /// Creates a new builder-style object to manufacture [`ConverseOutput`](crate::operation::converse::ConverseOutput).
    pub fn builder() -> crate::operation::converse::builders::ConverseOutputBuilder {
        crate::operation::converse::builders::ConverseOutputBuilder::default()
    }
}

/// A builder for [`ConverseOutput`](crate::operation::converse::ConverseOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConverseOutputBuilder {
    pub(crate) output: ::std::option::Option<crate::types::ConverseOutput>,
    pub(crate) stop_reason: ::std::option::Option<crate::types::StopReason>,
    pub(crate) usage: ::std::option::Option<crate::types::TokenUsage>,
    pub(crate) metrics: ::std::option::Option<crate::types::ConverseMetrics>,
    pub(crate) additional_model_response_fields: ::std::option::Option<::aws_smithy_types::Document>,
    pub(crate) trace: ::std::option::Option<crate::types::ConverseTrace>,
    pub(crate) performance_config: ::std::option::Option<crate::types::PerformanceConfiguration>,
    _request_id: Option<String>,
}
impl ConverseOutputBuilder {
    /// <p>The result from the call to <code>Converse</code>.</p>
    /// This field is required.
    pub fn output(mut self, input: crate::types::ConverseOutput) -> Self {
        self.output = ::std::option::Option::Some(input);
        self
    }
    /// <p>The result from the call to <code>Converse</code>.</p>
    pub fn set_output(mut self, input: ::std::option::Option<crate::types::ConverseOutput>) -> Self {
        self.output = input;
        self
    }
    /// <p>The result from the call to <code>Converse</code>.</p>
    pub fn get_output(&self) -> &::std::option::Option<crate::types::ConverseOutput> {
        &self.output
    }
    /// <p>The reason why the model stopped generating output.</p>
    /// This field is required.
    pub fn stop_reason(mut self, input: crate::types::StopReason) -> Self {
        self.stop_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason why the model stopped generating output.</p>
    pub fn set_stop_reason(mut self, input: ::std::option::Option<crate::types::StopReason>) -> Self {
        self.stop_reason = input;
        self
    }
    /// <p>The reason why the model stopped generating output.</p>
    pub fn get_stop_reason(&self) -> &::std::option::Option<crate::types::StopReason> {
        &self.stop_reason
    }
    /// <p>The total number of tokens used in the call to <code>Converse</code>. The total includes the tokens input to the model and the tokens generated by the model.</p>
    /// This field is required.
    pub fn usage(mut self, input: crate::types::TokenUsage) -> Self {
        self.usage = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of tokens used in the call to <code>Converse</code>. The total includes the tokens input to the model and the tokens generated by the model.</p>
    pub fn set_usage(mut self, input: ::std::option::Option<crate::types::TokenUsage>) -> Self {
        self.usage = input;
        self
    }
    /// <p>The total number of tokens used in the call to <code>Converse</code>. The total includes the tokens input to the model and the tokens generated by the model.</p>
    pub fn get_usage(&self) -> &::std::option::Option<crate::types::TokenUsage> {
        &self.usage
    }
    /// <p>Metrics for the call to <code>Converse</code>.</p>
    /// This field is required.
    pub fn metrics(mut self, input: crate::types::ConverseMetrics) -> Self {
        self.metrics = ::std::option::Option::Some(input);
        self
    }
    /// <p>Metrics for the call to <code>Converse</code>.</p>
    pub fn set_metrics(mut self, input: ::std::option::Option<crate::types::ConverseMetrics>) -> Self {
        self.metrics = input;
        self
    }
    /// <p>Metrics for the call to <code>Converse</code>.</p>
    pub fn get_metrics(&self) -> &::std::option::Option<crate::types::ConverseMetrics> {
        &self.metrics
    }
    /// <p>Additional fields in the response that are unique to the model.</p>
    pub fn additional_model_response_fields(mut self, input: ::aws_smithy_types::Document) -> Self {
        self.additional_model_response_fields = ::std::option::Option::Some(input);
        self
    }
    /// <p>Additional fields in the response that are unique to the model.</p>
    pub fn set_additional_model_response_fields(mut self, input: ::std::option::Option<::aws_smithy_types::Document>) -> Self {
        self.additional_model_response_fields = input;
        self
    }
    /// <p>Additional fields in the response that are unique to the model.</p>
    pub fn get_additional_model_response_fields(&self) -> &::std::option::Option<::aws_smithy_types::Document> {
        &self.additional_model_response_fields
    }
    /// <p>A trace object that contains information about the Guardrail behavior.</p>
    pub fn trace(mut self, input: crate::types::ConverseTrace) -> Self {
        self.trace = ::std::option::Option::Some(input);
        self
    }
    /// <p>A trace object that contains information about the Guardrail behavior.</p>
    pub fn set_trace(mut self, input: ::std::option::Option<crate::types::ConverseTrace>) -> Self {
        self.trace = input;
        self
    }
    /// <p>A trace object that contains information about the Guardrail behavior.</p>
    pub fn get_trace(&self) -> &::std::option::Option<crate::types::ConverseTrace> {
        &self.trace
    }
    /// <p>Model performance settings for the request.</p>
    pub fn performance_config(mut self, input: crate::types::PerformanceConfiguration) -> Self {
        self.performance_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Model performance settings for the request.</p>
    pub fn set_performance_config(mut self, input: ::std::option::Option<crate::types::PerformanceConfiguration>) -> Self {
        self.performance_config = input;
        self
    }
    /// <p>Model performance settings for the request.</p>
    pub fn get_performance_config(&self) -> &::std::option::Option<crate::types::PerformanceConfiguration> {
        &self.performance_config
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ConverseOutput`](crate::operation::converse::ConverseOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`stop_reason`](crate::operation::converse::builders::ConverseOutputBuilder::stop_reason)
    pub fn build(self) -> ::std::result::Result<crate::operation::converse::ConverseOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::converse::ConverseOutput {
            output: self.output,
            stop_reason: self.stop_reason.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "stop_reason",
                    "stop_reason was not specified but it is required when building ConverseOutput",
                )
            })?,
            usage: self.usage,
            metrics: self.metrics,
            additional_model_response_fields: self.additional_model_response_fields,
            trace: self.trace,
            performance_config: self.performance_config,
            _request_id: self._request_id,
        })
    }
}
