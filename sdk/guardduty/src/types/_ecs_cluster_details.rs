// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the details of the ECS Cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EcsClusterDetails {
    /// <p>The name of the ECS Cluster.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) that identifies the cluster.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The status of the ECS cluster.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The number of services that are running on the cluster in an ACTIVE state.</p>
    pub active_services_count: ::std::option::Option<i32>,
    /// <p>The number of container instances registered into the cluster.</p>
    pub registered_container_instances_count: ::std::option::Option<i32>,
    /// <p>The number of tasks in the cluster that are in the RUNNING state.</p>
    pub running_tasks_count: ::std::option::Option<i32>,
    /// <p>The tags of the ECS Cluster.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>Contains information about the details of the ECS Task.</p>
    pub task_details: ::std::option::Option<crate::types::EcsTaskDetails>,
}
impl EcsClusterDetails {
    /// <p>The name of the ECS Cluster.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the cluster.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The status of the ECS cluster.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The number of services that are running on the cluster in an ACTIVE state.</p>
    pub fn active_services_count(&self) -> ::std::option::Option<i32> {
        self.active_services_count
    }
    /// <p>The number of container instances registered into the cluster.</p>
    pub fn registered_container_instances_count(&self) -> ::std::option::Option<i32> {
        self.registered_container_instances_count
    }
    /// <p>The number of tasks in the cluster that are in the RUNNING state.</p>
    pub fn running_tasks_count(&self) -> ::std::option::Option<i32> {
        self.running_tasks_count
    }
    /// <p>The tags of the ECS Cluster.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>Contains information about the details of the ECS Task.</p>
    pub fn task_details(&self) -> ::std::option::Option<&crate::types::EcsTaskDetails> {
        self.task_details.as_ref()
    }
}
impl EcsClusterDetails {
    /// Creates a new builder-style object to manufacture [`EcsClusterDetails`](crate::types::EcsClusterDetails).
    pub fn builder() -> crate::types::builders::EcsClusterDetailsBuilder {
        crate::types::builders::EcsClusterDetailsBuilder::default()
    }
}

/// A builder for [`EcsClusterDetails`](crate::types::EcsClusterDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EcsClusterDetailsBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) active_services_count: ::std::option::Option<i32>,
    pub(crate) registered_container_instances_count: ::std::option::Option<i32>,
    pub(crate) running_tasks_count: ::std::option::Option<i32>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) task_details: ::std::option::Option<crate::types::EcsTaskDetails>,
}
impl EcsClusterDetailsBuilder {
    /// <p>The name of the ECS Cluster.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the ECS Cluster.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the ECS Cluster.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the cluster.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the cluster.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that identifies the cluster.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The status of the ECS cluster.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the ECS cluster.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the ECS cluster.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The number of services that are running on the cluster in an ACTIVE state.</p>
    pub fn active_services_count(mut self, input: i32) -> Self {
        self.active_services_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of services that are running on the cluster in an ACTIVE state.</p>
    pub fn set_active_services_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.active_services_count = input;
        self
    }
    /// <p>The number of services that are running on the cluster in an ACTIVE state.</p>
    pub fn get_active_services_count(&self) -> &::std::option::Option<i32> {
        &self.active_services_count
    }
    /// <p>The number of container instances registered into the cluster.</p>
    pub fn registered_container_instances_count(mut self, input: i32) -> Self {
        self.registered_container_instances_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of container instances registered into the cluster.</p>
    pub fn set_registered_container_instances_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.registered_container_instances_count = input;
        self
    }
    /// <p>The number of container instances registered into the cluster.</p>
    pub fn get_registered_container_instances_count(&self) -> &::std::option::Option<i32> {
        &self.registered_container_instances_count
    }
    /// <p>The number of tasks in the cluster that are in the RUNNING state.</p>
    pub fn running_tasks_count(mut self, input: i32) -> Self {
        self.running_tasks_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of tasks in the cluster that are in the RUNNING state.</p>
    pub fn set_running_tasks_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.running_tasks_count = input;
        self
    }
    /// <p>The number of tasks in the cluster that are in the RUNNING state.</p>
    pub fn get_running_tasks_count(&self) -> &::std::option::Option<i32> {
        &self.running_tasks_count
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags of the ECS Cluster.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags of the ECS Cluster.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags of the ECS Cluster.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>Contains information about the details of the ECS Task.</p>
    pub fn task_details(mut self, input: crate::types::EcsTaskDetails) -> Self {
        self.task_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains information about the details of the ECS Task.</p>
    pub fn set_task_details(mut self, input: ::std::option::Option<crate::types::EcsTaskDetails>) -> Self {
        self.task_details = input;
        self
    }
    /// <p>Contains information about the details of the ECS Task.</p>
    pub fn get_task_details(&self) -> &::std::option::Option<crate::types::EcsTaskDetails> {
        &self.task_details
    }
    /// Consumes the builder and constructs a [`EcsClusterDetails`](crate::types::EcsClusterDetails).
    pub fn build(self) -> crate::types::EcsClusterDetails {
        crate::types::EcsClusterDetails {
            name: self.name,
            arn: self.arn,
            status: self.status,
            active_services_count: self.active_services_count,
            registered_container_instances_count: self.registered_container_instances_count,
            running_tasks_count: self.running_tasks_count,
            tags: self.tags,
            task_details: self.task_details,
        }
    }
}
