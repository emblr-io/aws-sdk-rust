// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of recommendations made by Amazon SageMaker Inference Recommender.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InferenceRecommendation {
    /// <p>The recommendation ID which uniquely identifies each recommendation.</p>
    pub recommendation_id: ::std::option::Option<::std::string::String>,
    /// <p>The metrics used to decide what recommendation to make.</p>
    pub metrics: ::std::option::Option<crate::types::RecommendationMetrics>,
    /// <p>Defines the endpoint configuration parameters.</p>
    pub endpoint_configuration: ::std::option::Option<crate::types::EndpointOutputConfiguration>,
    /// <p>Defines the model configuration.</p>
    pub model_configuration: ::std::option::Option<crate::types::ModelConfiguration>,
    /// <p>A timestamp that shows when the benchmark completed.</p>
    pub invocation_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A timestamp that shows when the benchmark started.</p>
    pub invocation_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl InferenceRecommendation {
    /// <p>The recommendation ID which uniquely identifies each recommendation.</p>
    pub fn recommendation_id(&self) -> ::std::option::Option<&str> {
        self.recommendation_id.as_deref()
    }
    /// <p>The metrics used to decide what recommendation to make.</p>
    pub fn metrics(&self) -> ::std::option::Option<&crate::types::RecommendationMetrics> {
        self.metrics.as_ref()
    }
    /// <p>Defines the endpoint configuration parameters.</p>
    pub fn endpoint_configuration(&self) -> ::std::option::Option<&crate::types::EndpointOutputConfiguration> {
        self.endpoint_configuration.as_ref()
    }
    /// <p>Defines the model configuration.</p>
    pub fn model_configuration(&self) -> ::std::option::Option<&crate::types::ModelConfiguration> {
        self.model_configuration.as_ref()
    }
    /// <p>A timestamp that shows when the benchmark completed.</p>
    pub fn invocation_end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.invocation_end_time.as_ref()
    }
    /// <p>A timestamp that shows when the benchmark started.</p>
    pub fn invocation_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.invocation_start_time.as_ref()
    }
}
impl InferenceRecommendation {
    /// Creates a new builder-style object to manufacture [`InferenceRecommendation`](crate::types::InferenceRecommendation).
    pub fn builder() -> crate::types::builders::InferenceRecommendationBuilder {
        crate::types::builders::InferenceRecommendationBuilder::default()
    }
}

/// A builder for [`InferenceRecommendation`](crate::types::InferenceRecommendation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InferenceRecommendationBuilder {
    pub(crate) recommendation_id: ::std::option::Option<::std::string::String>,
    pub(crate) metrics: ::std::option::Option<crate::types::RecommendationMetrics>,
    pub(crate) endpoint_configuration: ::std::option::Option<crate::types::EndpointOutputConfiguration>,
    pub(crate) model_configuration: ::std::option::Option<crate::types::ModelConfiguration>,
    pub(crate) invocation_end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) invocation_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl InferenceRecommendationBuilder {
    /// <p>The recommendation ID which uniquely identifies each recommendation.</p>
    pub fn recommendation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The recommendation ID which uniquely identifies each recommendation.</p>
    pub fn set_recommendation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_id = input;
        self
    }
    /// <p>The recommendation ID which uniquely identifies each recommendation.</p>
    pub fn get_recommendation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_id
    }
    /// <p>The metrics used to decide what recommendation to make.</p>
    pub fn metrics(mut self, input: crate::types::RecommendationMetrics) -> Self {
        self.metrics = ::std::option::Option::Some(input);
        self
    }
    /// <p>The metrics used to decide what recommendation to make.</p>
    pub fn set_metrics(mut self, input: ::std::option::Option<crate::types::RecommendationMetrics>) -> Self {
        self.metrics = input;
        self
    }
    /// <p>The metrics used to decide what recommendation to make.</p>
    pub fn get_metrics(&self) -> &::std::option::Option<crate::types::RecommendationMetrics> {
        &self.metrics
    }
    /// <p>Defines the endpoint configuration parameters.</p>
    /// This field is required.
    pub fn endpoint_configuration(mut self, input: crate::types::EndpointOutputConfiguration) -> Self {
        self.endpoint_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the endpoint configuration parameters.</p>
    pub fn set_endpoint_configuration(mut self, input: ::std::option::Option<crate::types::EndpointOutputConfiguration>) -> Self {
        self.endpoint_configuration = input;
        self
    }
    /// <p>Defines the endpoint configuration parameters.</p>
    pub fn get_endpoint_configuration(&self) -> &::std::option::Option<crate::types::EndpointOutputConfiguration> {
        &self.endpoint_configuration
    }
    /// <p>Defines the model configuration.</p>
    /// This field is required.
    pub fn model_configuration(mut self, input: crate::types::ModelConfiguration) -> Self {
        self.model_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines the model configuration.</p>
    pub fn set_model_configuration(mut self, input: ::std::option::Option<crate::types::ModelConfiguration>) -> Self {
        self.model_configuration = input;
        self
    }
    /// <p>Defines the model configuration.</p>
    pub fn get_model_configuration(&self) -> &::std::option::Option<crate::types::ModelConfiguration> {
        &self.model_configuration
    }
    /// <p>A timestamp that shows when the benchmark completed.</p>
    pub fn invocation_end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.invocation_end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that shows when the benchmark completed.</p>
    pub fn set_invocation_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.invocation_end_time = input;
        self
    }
    /// <p>A timestamp that shows when the benchmark completed.</p>
    pub fn get_invocation_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.invocation_end_time
    }
    /// <p>A timestamp that shows when the benchmark started.</p>
    pub fn invocation_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.invocation_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that shows when the benchmark started.</p>
    pub fn set_invocation_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.invocation_start_time = input;
        self
    }
    /// <p>A timestamp that shows when the benchmark started.</p>
    pub fn get_invocation_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.invocation_start_time
    }
    /// Consumes the builder and constructs a [`InferenceRecommendation`](crate::types::InferenceRecommendation).
    pub fn build(self) -> crate::types::InferenceRecommendation {
        crate::types::InferenceRecommendation {
            recommendation_id: self.recommendation_id,
            metrics: self.metrics,
            endpoint_configuration: self.endpoint_configuration,
            model_configuration: self.model_configuration,
            invocation_end_time: self.invocation_end_time,
            invocation_start_time: self.invocation_start_time,
        }
    }
}
