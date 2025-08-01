// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the resources that are deployed with this inference component.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InferenceComponentSpecificationSummary {
    /// <p>The name of the SageMaker AI model object that is deployed with the inference component.</p>
    pub model_name: ::std::option::Option<::std::string::String>,
    /// <p>Details about the container that provides the runtime environment for the model that is deployed with the inference component.</p>
    pub container: ::std::option::Option<crate::types::InferenceComponentContainerSpecificationSummary>,
    /// <p>Settings that take effect while the model container starts up.</p>
    pub startup_parameters: ::std::option::Option<crate::types::InferenceComponentStartupParameters>,
    /// <p>The compute resources allocated to run the model, plus any adapter models, that you assign to the inference component.</p>
    pub compute_resource_requirements: ::std::option::Option<crate::types::InferenceComponentComputeResourceRequirements>,
    /// <p>The name of the base inference component that contains this inference component.</p>
    pub base_inference_component_name: ::std::option::Option<::std::string::String>,
}
impl InferenceComponentSpecificationSummary {
    /// <p>The name of the SageMaker AI model object that is deployed with the inference component.</p>
    pub fn model_name(&self) -> ::std::option::Option<&str> {
        self.model_name.as_deref()
    }
    /// <p>Details about the container that provides the runtime environment for the model that is deployed with the inference component.</p>
    pub fn container(&self) -> ::std::option::Option<&crate::types::InferenceComponentContainerSpecificationSummary> {
        self.container.as_ref()
    }
    /// <p>Settings that take effect while the model container starts up.</p>
    pub fn startup_parameters(&self) -> ::std::option::Option<&crate::types::InferenceComponentStartupParameters> {
        self.startup_parameters.as_ref()
    }
    /// <p>The compute resources allocated to run the model, plus any adapter models, that you assign to the inference component.</p>
    pub fn compute_resource_requirements(&self) -> ::std::option::Option<&crate::types::InferenceComponentComputeResourceRequirements> {
        self.compute_resource_requirements.as_ref()
    }
    /// <p>The name of the base inference component that contains this inference component.</p>
    pub fn base_inference_component_name(&self) -> ::std::option::Option<&str> {
        self.base_inference_component_name.as_deref()
    }
}
impl InferenceComponentSpecificationSummary {
    /// Creates a new builder-style object to manufacture [`InferenceComponentSpecificationSummary`](crate::types::InferenceComponentSpecificationSummary).
    pub fn builder() -> crate::types::builders::InferenceComponentSpecificationSummaryBuilder {
        crate::types::builders::InferenceComponentSpecificationSummaryBuilder::default()
    }
}

/// A builder for [`InferenceComponentSpecificationSummary`](crate::types::InferenceComponentSpecificationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InferenceComponentSpecificationSummaryBuilder {
    pub(crate) model_name: ::std::option::Option<::std::string::String>,
    pub(crate) container: ::std::option::Option<crate::types::InferenceComponentContainerSpecificationSummary>,
    pub(crate) startup_parameters: ::std::option::Option<crate::types::InferenceComponentStartupParameters>,
    pub(crate) compute_resource_requirements: ::std::option::Option<crate::types::InferenceComponentComputeResourceRequirements>,
    pub(crate) base_inference_component_name: ::std::option::Option<::std::string::String>,
}
impl InferenceComponentSpecificationSummaryBuilder {
    /// <p>The name of the SageMaker AI model object that is deployed with the inference component.</p>
    pub fn model_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the SageMaker AI model object that is deployed with the inference component.</p>
    pub fn set_model_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_name = input;
        self
    }
    /// <p>The name of the SageMaker AI model object that is deployed with the inference component.</p>
    pub fn get_model_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_name
    }
    /// <p>Details about the container that provides the runtime environment for the model that is deployed with the inference component.</p>
    pub fn container(mut self, input: crate::types::InferenceComponentContainerSpecificationSummary) -> Self {
        self.container = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the container that provides the runtime environment for the model that is deployed with the inference component.</p>
    pub fn set_container(mut self, input: ::std::option::Option<crate::types::InferenceComponentContainerSpecificationSummary>) -> Self {
        self.container = input;
        self
    }
    /// <p>Details about the container that provides the runtime environment for the model that is deployed with the inference component.</p>
    pub fn get_container(&self) -> &::std::option::Option<crate::types::InferenceComponentContainerSpecificationSummary> {
        &self.container
    }
    /// <p>Settings that take effect while the model container starts up.</p>
    pub fn startup_parameters(mut self, input: crate::types::InferenceComponentStartupParameters) -> Self {
        self.startup_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings that take effect while the model container starts up.</p>
    pub fn set_startup_parameters(mut self, input: ::std::option::Option<crate::types::InferenceComponentStartupParameters>) -> Self {
        self.startup_parameters = input;
        self
    }
    /// <p>Settings that take effect while the model container starts up.</p>
    pub fn get_startup_parameters(&self) -> &::std::option::Option<crate::types::InferenceComponentStartupParameters> {
        &self.startup_parameters
    }
    /// <p>The compute resources allocated to run the model, plus any adapter models, that you assign to the inference component.</p>
    pub fn compute_resource_requirements(mut self, input: crate::types::InferenceComponentComputeResourceRequirements) -> Self {
        self.compute_resource_requirements = ::std::option::Option::Some(input);
        self
    }
    /// <p>The compute resources allocated to run the model, plus any adapter models, that you assign to the inference component.</p>
    pub fn set_compute_resource_requirements(
        mut self,
        input: ::std::option::Option<crate::types::InferenceComponentComputeResourceRequirements>,
    ) -> Self {
        self.compute_resource_requirements = input;
        self
    }
    /// <p>The compute resources allocated to run the model, plus any adapter models, that you assign to the inference component.</p>
    pub fn get_compute_resource_requirements(&self) -> &::std::option::Option<crate::types::InferenceComponentComputeResourceRequirements> {
        &self.compute_resource_requirements
    }
    /// <p>The name of the base inference component that contains this inference component.</p>
    pub fn base_inference_component_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.base_inference_component_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the base inference component that contains this inference component.</p>
    pub fn set_base_inference_component_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.base_inference_component_name = input;
        self
    }
    /// <p>The name of the base inference component that contains this inference component.</p>
    pub fn get_base_inference_component_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.base_inference_component_name
    }
    /// Consumes the builder and constructs a [`InferenceComponentSpecificationSummary`](crate::types::InferenceComponentSpecificationSummary).
    pub fn build(self) -> crate::types::InferenceComponentSpecificationSummary {
        crate::types::InferenceComponentSpecificationSummary {
            model_name: self.model_name,
            container: self.container,
            startup_parameters: self.startup_parameters,
            compute_resource_requirements: self.compute_resource_requirements,
            base_inference_component_name: self.base_inference_component_name,
        }
    }
}
