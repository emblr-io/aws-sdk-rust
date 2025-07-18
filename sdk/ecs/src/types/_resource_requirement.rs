// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The type and amount of a resource to assign to a container. The supported resource types are GPUs and Elastic Inference accelerators. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-gpu.html">Working with GPUs on Amazon ECS</a> or <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-inference.html">Working with Amazon Elastic Inference on Amazon ECS</a> in the <i>Amazon Elastic Container Service Developer Guide</i></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResourceRequirement {
    /// <p>The value for the specified resource type.</p>
    /// <p>When the type is <code>GPU</code>, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>When the type is <code>InferenceAccelerator</code>, the <code>value</code> matches the <code>deviceName</code> for an <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_InferenceAccelerator.html">InferenceAccelerator</a> specified in a task definition.</p>
    pub value: ::std::string::String,
    /// <p>The type of resource to assign to a container.</p>
    pub r#type: crate::types::ResourceType,
}
impl ResourceRequirement {
    /// <p>The value for the specified resource type.</p>
    /// <p>When the type is <code>GPU</code>, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>When the type is <code>InferenceAccelerator</code>, the <code>value</code> matches the <code>deviceName</code> for an <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_InferenceAccelerator.html">InferenceAccelerator</a> specified in a task definition.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
    /// <p>The type of resource to assign to a container.</p>
    pub fn r#type(&self) -> &crate::types::ResourceType {
        &self.r#type
    }
}
impl ResourceRequirement {
    /// Creates a new builder-style object to manufacture [`ResourceRequirement`](crate::types::ResourceRequirement).
    pub fn builder() -> crate::types::builders::ResourceRequirementBuilder {
        crate::types::builders::ResourceRequirementBuilder::default()
    }
}

/// A builder for [`ResourceRequirement`](crate::types::ResourceRequirement).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResourceRequirementBuilder {
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::ResourceType>,
}
impl ResourceRequirementBuilder {
    /// <p>The value for the specified resource type.</p>
    /// <p>When the type is <code>GPU</code>, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>When the type is <code>InferenceAccelerator</code>, the <code>value</code> matches the <code>deviceName</code> for an <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_InferenceAccelerator.html">InferenceAccelerator</a> specified in a task definition.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value for the specified resource type.</p>
    /// <p>When the type is <code>GPU</code>, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>When the type is <code>InferenceAccelerator</code>, the <code>value</code> matches the <code>deviceName</code> for an <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_InferenceAccelerator.html">InferenceAccelerator</a> specified in a task definition.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value for the specified resource type.</p>
    /// <p>When the type is <code>GPU</code>, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>When the type is <code>InferenceAccelerator</code>, the <code>value</code> matches the <code>deviceName</code> for an <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_InferenceAccelerator.html">InferenceAccelerator</a> specified in a task definition.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The type of resource to assign to a container.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::ResourceType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resource to assign to a container.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::ResourceType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of resource to assign to a container.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::ResourceType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`ResourceRequirement`](crate::types::ResourceRequirement).
    /// This method will fail if any of the following fields are not set:
    /// - [`value`](crate::types::builders::ResourceRequirementBuilder::value)
    /// - [`r#type`](crate::types::builders::ResourceRequirementBuilder::type)
    pub fn build(self) -> ::std::result::Result<crate::types::ResourceRequirement, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ResourceRequirement {
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building ResourceRequirement",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building ResourceRequirement",
                )
            })?,
        })
    }
}
