// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The type and amount of a resource to assign to a container. The supported resource types are GPUs and Elastic Inference accelerators. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-gpu.html">Working with GPUs on Amazon ECS</a> or <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-inference.html">Working with Amazon Elastic Inference on Amazon ECS</a> in the <i>Amazon Elastic Container Service Developer Guide</i></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EcsResourceRequirement {
    /// <p>The type of resource to assign to a container. The supported values are <code>GPU</code> or <code>InferenceAccelerator</code>.</p>
    pub r#type: crate::types::EcsResourceRequirementType,
    /// <p>The value for the specified resource type.</p>
    /// <p>If the <code>GPU</code> type is used, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>If the <code>InferenceAccelerator</code> type is used, the <code>value</code> matches the <code>deviceName</code> for an InferenceAccelerator specified in a task definition.</p>
    pub value: ::std::string::String,
}
impl EcsResourceRequirement {
    /// <p>The type of resource to assign to a container. The supported values are <code>GPU</code> or <code>InferenceAccelerator</code>.</p>
    pub fn r#type(&self) -> &crate::types::EcsResourceRequirementType {
        &self.r#type
    }
    /// <p>The value for the specified resource type.</p>
    /// <p>If the <code>GPU</code> type is used, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>If the <code>InferenceAccelerator</code> type is used, the <code>value</code> matches the <code>deviceName</code> for an InferenceAccelerator specified in a task definition.</p>
    pub fn value(&self) -> &str {
        use std::ops::Deref;
        self.value.deref()
    }
}
impl EcsResourceRequirement {
    /// Creates a new builder-style object to manufacture [`EcsResourceRequirement`](crate::types::EcsResourceRequirement).
    pub fn builder() -> crate::types::builders::EcsResourceRequirementBuilder {
        crate::types::builders::EcsResourceRequirementBuilder::default()
    }
}

/// A builder for [`EcsResourceRequirement`](crate::types::EcsResourceRequirement).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EcsResourceRequirementBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::EcsResourceRequirementType>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl EcsResourceRequirementBuilder {
    /// <p>The type of resource to assign to a container. The supported values are <code>GPU</code> or <code>InferenceAccelerator</code>.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::EcsResourceRequirementType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of resource to assign to a container. The supported values are <code>GPU</code> or <code>InferenceAccelerator</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::EcsResourceRequirementType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of resource to assign to a container. The supported values are <code>GPU</code> or <code>InferenceAccelerator</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::EcsResourceRequirementType> {
        &self.r#type
    }
    /// <p>The value for the specified resource type.</p>
    /// <p>If the <code>GPU</code> type is used, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>If the <code>InferenceAccelerator</code> type is used, the <code>value</code> matches the <code>deviceName</code> for an InferenceAccelerator specified in a task definition.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value for the specified resource type.</p>
    /// <p>If the <code>GPU</code> type is used, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>If the <code>InferenceAccelerator</code> type is used, the <code>value</code> matches the <code>deviceName</code> for an InferenceAccelerator specified in a task definition.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The value for the specified resource type.</p>
    /// <p>If the <code>GPU</code> type is used, the value is the number of physical <code>GPUs</code> the Amazon ECS container agent reserves for the container. The number of GPUs that's reserved for all containers in a task can't exceed the number of available GPUs on the container instance that the task is launched on.</p>
    /// <p>If the <code>InferenceAccelerator</code> type is used, the <code>value</code> matches the <code>deviceName</code> for an InferenceAccelerator specified in a task definition.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`EcsResourceRequirement`](crate::types::EcsResourceRequirement).
    /// This method will fail if any of the following fields are not set:
    /// - [`r#type`](crate::types::builders::EcsResourceRequirementBuilder::type)
    /// - [`value`](crate::types::builders::EcsResourceRequirementBuilder::value)
    pub fn build(self) -> ::std::result::Result<crate::types::EcsResourceRequirement, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EcsResourceRequirement {
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building EcsResourceRequirement",
                )
            })?,
            value: self.value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "value",
                    "value was not specified but it is required when building EcsResourceRequirement",
                )
            })?,
        })
    }
}
