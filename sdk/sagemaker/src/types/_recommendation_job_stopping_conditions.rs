// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies conditions for stopping a job. When a job reaches a stopping condition limit, SageMaker ends the job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecommendationJobStoppingConditions {
    /// <p>The maximum number of requests per minute expected for the endpoint.</p>
    pub max_invocations: ::std::option::Option<i32>,
    /// <p>The interval of time taken by a model to respond as viewed from SageMaker. The interval includes the local communication time taken to send the request and to fetch the response from the container of a model and the time taken to complete the inference in the container.</p>
    pub model_latency_thresholds: ::std::option::Option<::std::vec::Vec<crate::types::ModelLatencyThreshold>>,
    /// <p>Stops a load test when the number of invocations (TPS) peaks and flattens, which means that the instance has reached capacity. The default value is <code>Stop</code>. If you want the load test to continue after invocations have flattened, set the value to <code>Continue</code>.</p>
    pub flat_invocations: ::std::option::Option<crate::types::FlatInvocations>,
}
impl RecommendationJobStoppingConditions {
    /// <p>The maximum number of requests per minute expected for the endpoint.</p>
    pub fn max_invocations(&self) -> ::std::option::Option<i32> {
        self.max_invocations
    }
    /// <p>The interval of time taken by a model to respond as viewed from SageMaker. The interval includes the local communication time taken to send the request and to fetch the response from the container of a model and the time taken to complete the inference in the container.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.model_latency_thresholds.is_none()`.
    pub fn model_latency_thresholds(&self) -> &[crate::types::ModelLatencyThreshold] {
        self.model_latency_thresholds.as_deref().unwrap_or_default()
    }
    /// <p>Stops a load test when the number of invocations (TPS) peaks and flattens, which means that the instance has reached capacity. The default value is <code>Stop</code>. If you want the load test to continue after invocations have flattened, set the value to <code>Continue</code>.</p>
    pub fn flat_invocations(&self) -> ::std::option::Option<&crate::types::FlatInvocations> {
        self.flat_invocations.as_ref()
    }
}
impl RecommendationJobStoppingConditions {
    /// Creates a new builder-style object to manufacture [`RecommendationJobStoppingConditions`](crate::types::RecommendationJobStoppingConditions).
    pub fn builder() -> crate::types::builders::RecommendationJobStoppingConditionsBuilder {
        crate::types::builders::RecommendationJobStoppingConditionsBuilder::default()
    }
}

/// A builder for [`RecommendationJobStoppingConditions`](crate::types::RecommendationJobStoppingConditions).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecommendationJobStoppingConditionsBuilder {
    pub(crate) max_invocations: ::std::option::Option<i32>,
    pub(crate) model_latency_thresholds: ::std::option::Option<::std::vec::Vec<crate::types::ModelLatencyThreshold>>,
    pub(crate) flat_invocations: ::std::option::Option<crate::types::FlatInvocations>,
}
impl RecommendationJobStoppingConditionsBuilder {
    /// <p>The maximum number of requests per minute expected for the endpoint.</p>
    pub fn max_invocations(mut self, input: i32) -> Self {
        self.max_invocations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of requests per minute expected for the endpoint.</p>
    pub fn set_max_invocations(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_invocations = input;
        self
    }
    /// <p>The maximum number of requests per minute expected for the endpoint.</p>
    pub fn get_max_invocations(&self) -> &::std::option::Option<i32> {
        &self.max_invocations
    }
    /// Appends an item to `model_latency_thresholds`.
    ///
    /// To override the contents of this collection use [`set_model_latency_thresholds`](Self::set_model_latency_thresholds).
    ///
    /// <p>The interval of time taken by a model to respond as viewed from SageMaker. The interval includes the local communication time taken to send the request and to fetch the response from the container of a model and the time taken to complete the inference in the container.</p>
    pub fn model_latency_thresholds(mut self, input: crate::types::ModelLatencyThreshold) -> Self {
        let mut v = self.model_latency_thresholds.unwrap_or_default();
        v.push(input);
        self.model_latency_thresholds = ::std::option::Option::Some(v);
        self
    }
    /// <p>The interval of time taken by a model to respond as viewed from SageMaker. The interval includes the local communication time taken to send the request and to fetch the response from the container of a model and the time taken to complete the inference in the container.</p>
    pub fn set_model_latency_thresholds(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ModelLatencyThreshold>>) -> Self {
        self.model_latency_thresholds = input;
        self
    }
    /// <p>The interval of time taken by a model to respond as viewed from SageMaker. The interval includes the local communication time taken to send the request and to fetch the response from the container of a model and the time taken to complete the inference in the container.</p>
    pub fn get_model_latency_thresholds(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ModelLatencyThreshold>> {
        &self.model_latency_thresholds
    }
    /// <p>Stops a load test when the number of invocations (TPS) peaks and flattens, which means that the instance has reached capacity. The default value is <code>Stop</code>. If you want the load test to continue after invocations have flattened, set the value to <code>Continue</code>.</p>
    pub fn flat_invocations(mut self, input: crate::types::FlatInvocations) -> Self {
        self.flat_invocations = ::std::option::Option::Some(input);
        self
    }
    /// <p>Stops a load test when the number of invocations (TPS) peaks and flattens, which means that the instance has reached capacity. The default value is <code>Stop</code>. If you want the load test to continue after invocations have flattened, set the value to <code>Continue</code>.</p>
    pub fn set_flat_invocations(mut self, input: ::std::option::Option<crate::types::FlatInvocations>) -> Self {
        self.flat_invocations = input;
        self
    }
    /// <p>Stops a load test when the number of invocations (TPS) peaks and flattens, which means that the instance has reached capacity. The default value is <code>Stop</code>. If you want the load test to continue after invocations have flattened, set the value to <code>Continue</code>.</p>
    pub fn get_flat_invocations(&self) -> &::std::option::Option<crate::types::FlatInvocations> {
        &self.flat_invocations
    }
    /// Consumes the builder and constructs a [`RecommendationJobStoppingConditions`](crate::types::RecommendationJobStoppingConditions).
    pub fn build(self) -> crate::types::RecommendationJobStoppingConditions {
        crate::types::RecommendationJobStoppingConditions {
            max_invocations: self.max_invocations,
            model_latency_thresholds: self.model_latency_thresholds,
            flat_invocations: self.flat_invocations,
        }
    }
}
