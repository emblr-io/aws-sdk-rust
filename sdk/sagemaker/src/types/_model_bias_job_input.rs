// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Inputs for the model bias job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModelBiasJobInput {
    /// <p>Input object for the endpoint</p>
    pub endpoint_input: ::std::option::Option<crate::types::EndpointInput>,
    /// <p>Input object for the batch transform job.</p>
    pub batch_transform_input: ::std::option::Option<crate::types::BatchTransformInput>,
    /// <p>Location of ground truth labels to use in model bias job.</p>
    pub ground_truth_s3_input: ::std::option::Option<crate::types::MonitoringGroundTruthS3Input>,
}
impl ModelBiasJobInput {
    /// <p>Input object for the endpoint</p>
    pub fn endpoint_input(&self) -> ::std::option::Option<&crate::types::EndpointInput> {
        self.endpoint_input.as_ref()
    }
    /// <p>Input object for the batch transform job.</p>
    pub fn batch_transform_input(&self) -> ::std::option::Option<&crate::types::BatchTransformInput> {
        self.batch_transform_input.as_ref()
    }
    /// <p>Location of ground truth labels to use in model bias job.</p>
    pub fn ground_truth_s3_input(&self) -> ::std::option::Option<&crate::types::MonitoringGroundTruthS3Input> {
        self.ground_truth_s3_input.as_ref()
    }
}
impl ModelBiasJobInput {
    /// Creates a new builder-style object to manufacture [`ModelBiasJobInput`](crate::types::ModelBiasJobInput).
    pub fn builder() -> crate::types::builders::ModelBiasJobInputBuilder {
        crate::types::builders::ModelBiasJobInputBuilder::default()
    }
}

/// A builder for [`ModelBiasJobInput`](crate::types::ModelBiasJobInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModelBiasJobInputBuilder {
    pub(crate) endpoint_input: ::std::option::Option<crate::types::EndpointInput>,
    pub(crate) batch_transform_input: ::std::option::Option<crate::types::BatchTransformInput>,
    pub(crate) ground_truth_s3_input: ::std::option::Option<crate::types::MonitoringGroundTruthS3Input>,
}
impl ModelBiasJobInputBuilder {
    /// <p>Input object for the endpoint</p>
    pub fn endpoint_input(mut self, input: crate::types::EndpointInput) -> Self {
        self.endpoint_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Input object for the endpoint</p>
    pub fn set_endpoint_input(mut self, input: ::std::option::Option<crate::types::EndpointInput>) -> Self {
        self.endpoint_input = input;
        self
    }
    /// <p>Input object for the endpoint</p>
    pub fn get_endpoint_input(&self) -> &::std::option::Option<crate::types::EndpointInput> {
        &self.endpoint_input
    }
    /// <p>Input object for the batch transform job.</p>
    pub fn batch_transform_input(mut self, input: crate::types::BatchTransformInput) -> Self {
        self.batch_transform_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Input object for the batch transform job.</p>
    pub fn set_batch_transform_input(mut self, input: ::std::option::Option<crate::types::BatchTransformInput>) -> Self {
        self.batch_transform_input = input;
        self
    }
    /// <p>Input object for the batch transform job.</p>
    pub fn get_batch_transform_input(&self) -> &::std::option::Option<crate::types::BatchTransformInput> {
        &self.batch_transform_input
    }
    /// <p>Location of ground truth labels to use in model bias job.</p>
    /// This field is required.
    pub fn ground_truth_s3_input(mut self, input: crate::types::MonitoringGroundTruthS3Input) -> Self {
        self.ground_truth_s3_input = ::std::option::Option::Some(input);
        self
    }
    /// <p>Location of ground truth labels to use in model bias job.</p>
    pub fn set_ground_truth_s3_input(mut self, input: ::std::option::Option<crate::types::MonitoringGroundTruthS3Input>) -> Self {
        self.ground_truth_s3_input = input;
        self
    }
    /// <p>Location of ground truth labels to use in model bias job.</p>
    pub fn get_ground_truth_s3_input(&self) -> &::std::option::Option<crate::types::MonitoringGroundTruthS3Input> {
        &self.ground_truth_s3_input
    }
    /// Consumes the builder and constructs a [`ModelBiasJobInput`](crate::types::ModelBiasJobInput).
    pub fn build(self) -> crate::types::ModelBiasJobInput {
        crate::types::ModelBiasJobInput {
            endpoint_input: self.endpoint_input,
            batch_transform_input: self.batch_transform_input,
            ground_truth_s3_input: self.ground_truth_s3_input,
        }
    }
}
