// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents the details of a task.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AttemptEcsTaskDetails {
    /// <p>The Amazon Resource Name (ARN) of the container instance that hosts the task.</p>
    pub container_instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the Amazon ECS task.</p>
    pub task_arn: ::std::option::Option<::std::string::String>,
    /// <p>A list of containers that are included in the <code>taskProperties</code> list.</p>
    pub containers: ::std::option::Option<::std::vec::Vec<crate::types::AttemptTaskContainerDetails>>,
}
impl AttemptEcsTaskDetails {
    /// <p>The Amazon Resource Name (ARN) of the container instance that hosts the task.</p>
    pub fn container_instance_arn(&self) -> ::std::option::Option<&str> {
        self.container_instance_arn.as_deref()
    }
    /// <p>The ARN of the Amazon ECS task.</p>
    pub fn task_arn(&self) -> ::std::option::Option<&str> {
        self.task_arn.as_deref()
    }
    /// <p>A list of containers that are included in the <code>taskProperties</code> list.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.containers.is_none()`.
    pub fn containers(&self) -> &[crate::types::AttemptTaskContainerDetails] {
        self.containers.as_deref().unwrap_or_default()
    }
}
impl AttemptEcsTaskDetails {
    /// Creates a new builder-style object to manufacture [`AttemptEcsTaskDetails`](crate::types::AttemptEcsTaskDetails).
    pub fn builder() -> crate::types::builders::AttemptEcsTaskDetailsBuilder {
        crate::types::builders::AttemptEcsTaskDetailsBuilder::default()
    }
}

/// A builder for [`AttemptEcsTaskDetails`](crate::types::AttemptEcsTaskDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AttemptEcsTaskDetailsBuilder {
    pub(crate) container_instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) task_arn: ::std::option::Option<::std::string::String>,
    pub(crate) containers: ::std::option::Option<::std::vec::Vec<crate::types::AttemptTaskContainerDetails>>,
}
impl AttemptEcsTaskDetailsBuilder {
    /// <p>The Amazon Resource Name (ARN) of the container instance that hosts the task.</p>
    pub fn container_instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the container instance that hosts the task.</p>
    pub fn set_container_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_instance_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the container instance that hosts the task.</p>
    pub fn get_container_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_instance_arn
    }
    /// <p>The ARN of the Amazon ECS task.</p>
    pub fn task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Amazon ECS task.</p>
    pub fn set_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_arn = input;
        self
    }
    /// <p>The ARN of the Amazon ECS task.</p>
    pub fn get_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_arn
    }
    /// Appends an item to `containers`.
    ///
    /// To override the contents of this collection use [`set_containers`](Self::set_containers).
    ///
    /// <p>A list of containers that are included in the <code>taskProperties</code> list.</p>
    pub fn containers(mut self, input: crate::types::AttemptTaskContainerDetails) -> Self {
        let mut v = self.containers.unwrap_or_default();
        v.push(input);
        self.containers = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of containers that are included in the <code>taskProperties</code> list.</p>
    pub fn set_containers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AttemptTaskContainerDetails>>) -> Self {
        self.containers = input;
        self
    }
    /// <p>A list of containers that are included in the <code>taskProperties</code> list.</p>
    pub fn get_containers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AttemptTaskContainerDetails>> {
        &self.containers
    }
    /// Consumes the builder and constructs a [`AttemptEcsTaskDetails`](crate::types::AttemptEcsTaskDetails).
    pub fn build(self) -> crate::types::AttemptEcsTaskDetails {
        crate::types::AttemptEcsTaskDetails {
            container_instance_arn: self.container_instance_arn,
            task_arn: self.task_arn,
            containers: self.containers,
        }
    }
}
