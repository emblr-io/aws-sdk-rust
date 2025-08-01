// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides details about a task in a cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEcsTaskDetails {
    /// <p>The Amazon Resource Name (ARN) of the cluster that hosts the task.</p>
    pub cluster_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the task definition that creates the task.</p>
    pub task_definition_arn: ::std::option::Option<::std::string::String>,
    /// <p>The version counter for the task.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The Unix timestamp for the time when the task was created. More specifically, it's for the time when the task entered the <code>PENDING</code> state.</p>
    pub created_at: ::std::option::Option<::std::string::String>,
    /// <p>The Unix timestamp for the time when the task started. More specifically, it's for the time when the task transitioned from the <code>PENDING</code> state to the <code>RUNNING</code> state.</p>
    pub started_at: ::std::option::Option<::std::string::String>,
    /// <p>The tag specified when a task is started. If an Amazon ECS service started the task, the <code>startedBy</code> parameter contains the deployment ID of that service.</p>
    pub started_by: ::std::option::Option<::std::string::String>,
    /// <p>The name of the task group that's associated with the task.</p>
    pub group: ::std::option::Option<::std::string::String>,
    /// <p>Details about the data volume that is used in a task definition.</p>
    pub volumes: ::std::option::Option<::std::vec::Vec<crate::types::AwsEcsTaskVolumeDetails>>,
    /// <p>The containers that are associated with the task.</p>
    pub containers: ::std::option::Option<::std::vec::Vec<crate::types::AwsEcsContainerDetails>>,
}
impl AwsEcsTaskDetails {
    /// <p>The Amazon Resource Name (ARN) of the cluster that hosts the task.</p>
    pub fn cluster_arn(&self) -> ::std::option::Option<&str> {
        self.cluster_arn.as_deref()
    }
    /// <p>The ARN of the task definition that creates the task.</p>
    pub fn task_definition_arn(&self) -> ::std::option::Option<&str> {
        self.task_definition_arn.as_deref()
    }
    /// <p>The version counter for the task.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The Unix timestamp for the time when the task was created. More specifically, it's for the time when the task entered the <code>PENDING</code> state.</p>
    pub fn created_at(&self) -> ::std::option::Option<&str> {
        self.created_at.as_deref()
    }
    /// <p>The Unix timestamp for the time when the task started. More specifically, it's for the time when the task transitioned from the <code>PENDING</code> state to the <code>RUNNING</code> state.</p>
    pub fn started_at(&self) -> ::std::option::Option<&str> {
        self.started_at.as_deref()
    }
    /// <p>The tag specified when a task is started. If an Amazon ECS service started the task, the <code>startedBy</code> parameter contains the deployment ID of that service.</p>
    pub fn started_by(&self) -> ::std::option::Option<&str> {
        self.started_by.as_deref()
    }
    /// <p>The name of the task group that's associated with the task.</p>
    pub fn group(&self) -> ::std::option::Option<&str> {
        self.group.as_deref()
    }
    /// <p>Details about the data volume that is used in a task definition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.volumes.is_none()`.
    pub fn volumes(&self) -> &[crate::types::AwsEcsTaskVolumeDetails] {
        self.volumes.as_deref().unwrap_or_default()
    }
    /// <p>The containers that are associated with the task.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.containers.is_none()`.
    pub fn containers(&self) -> &[crate::types::AwsEcsContainerDetails] {
        self.containers.as_deref().unwrap_or_default()
    }
}
impl AwsEcsTaskDetails {
    /// Creates a new builder-style object to manufacture [`AwsEcsTaskDetails`](crate::types::AwsEcsTaskDetails).
    pub fn builder() -> crate::types::builders::AwsEcsTaskDetailsBuilder {
        crate::types::builders::AwsEcsTaskDetailsBuilder::default()
    }
}

/// A builder for [`AwsEcsTaskDetails`](crate::types::AwsEcsTaskDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEcsTaskDetailsBuilder {
    pub(crate) cluster_arn: ::std::option::Option<::std::string::String>,
    pub(crate) task_definition_arn: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::std::string::String>,
    pub(crate) started_at: ::std::option::Option<::std::string::String>,
    pub(crate) started_by: ::std::option::Option<::std::string::String>,
    pub(crate) group: ::std::option::Option<::std::string::String>,
    pub(crate) volumes: ::std::option::Option<::std::vec::Vec<crate::types::AwsEcsTaskVolumeDetails>>,
    pub(crate) containers: ::std::option::Option<::std::vec::Vec<crate::types::AwsEcsContainerDetails>>,
}
impl AwsEcsTaskDetailsBuilder {
    /// <p>The Amazon Resource Name (ARN) of the cluster that hosts the task.</p>
    pub fn cluster_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cluster_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the cluster that hosts the task.</p>
    pub fn set_cluster_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cluster_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the cluster that hosts the task.</p>
    pub fn get_cluster_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.cluster_arn
    }
    /// <p>The ARN of the task definition that creates the task.</p>
    pub fn task_definition_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_definition_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the task definition that creates the task.</p>
    pub fn set_task_definition_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_definition_arn = input;
        self
    }
    /// <p>The ARN of the task definition that creates the task.</p>
    pub fn get_task_definition_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_definition_arn
    }
    /// <p>The version counter for the task.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version counter for the task.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version counter for the task.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The Unix timestamp for the time when the task was created. More specifically, it's for the time when the task entered the <code>PENDING</code> state.</p>
    pub fn created_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Unix timestamp for the time when the task was created. More specifically, it's for the time when the task entered the <code>PENDING</code> state.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The Unix timestamp for the time when the task was created. More specifically, it's for the time when the task entered the <code>PENDING</code> state.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_at
    }
    /// <p>The Unix timestamp for the time when the task started. More specifically, it's for the time when the task transitioned from the <code>PENDING</code> state to the <code>RUNNING</code> state.</p>
    pub fn started_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.started_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Unix timestamp for the time when the task started. More specifically, it's for the time when the task transitioned from the <code>PENDING</code> state to the <code>RUNNING</code> state.</p>
    pub fn set_started_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.started_at = input;
        self
    }
    /// <p>The Unix timestamp for the time when the task started. More specifically, it's for the time when the task transitioned from the <code>PENDING</code> state to the <code>RUNNING</code> state.</p>
    pub fn get_started_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.started_at
    }
    /// <p>The tag specified when a task is started. If an Amazon ECS service started the task, the <code>startedBy</code> parameter contains the deployment ID of that service.</p>
    pub fn started_by(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.started_by = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The tag specified when a task is started. If an Amazon ECS service started the task, the <code>startedBy</code> parameter contains the deployment ID of that service.</p>
    pub fn set_started_by(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.started_by = input;
        self
    }
    /// <p>The tag specified when a task is started. If an Amazon ECS service started the task, the <code>startedBy</code> parameter contains the deployment ID of that service.</p>
    pub fn get_started_by(&self) -> &::std::option::Option<::std::string::String> {
        &self.started_by
    }
    /// <p>The name of the task group that's associated with the task.</p>
    pub fn group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the task group that's associated with the task.</p>
    pub fn set_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group = input;
        self
    }
    /// <p>The name of the task group that's associated with the task.</p>
    pub fn get_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.group
    }
    /// Appends an item to `volumes`.
    ///
    /// To override the contents of this collection use [`set_volumes`](Self::set_volumes).
    ///
    /// <p>Details about the data volume that is used in a task definition.</p>
    pub fn volumes(mut self, input: crate::types::AwsEcsTaskVolumeDetails) -> Self {
        let mut v = self.volumes.unwrap_or_default();
        v.push(input);
        self.volumes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Details about the data volume that is used in a task definition.</p>
    pub fn set_volumes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AwsEcsTaskVolumeDetails>>) -> Self {
        self.volumes = input;
        self
    }
    /// <p>Details about the data volume that is used in a task definition.</p>
    pub fn get_volumes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsEcsTaskVolumeDetails>> {
        &self.volumes
    }
    /// Appends an item to `containers`.
    ///
    /// To override the contents of this collection use [`set_containers`](Self::set_containers).
    ///
    /// <p>The containers that are associated with the task.</p>
    pub fn containers(mut self, input: crate::types::AwsEcsContainerDetails) -> Self {
        let mut v = self.containers.unwrap_or_default();
        v.push(input);
        self.containers = ::std::option::Option::Some(v);
        self
    }
    /// <p>The containers that are associated with the task.</p>
    pub fn set_containers(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AwsEcsContainerDetails>>) -> Self {
        self.containers = input;
        self
    }
    /// <p>The containers that are associated with the task.</p>
    pub fn get_containers(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AwsEcsContainerDetails>> {
        &self.containers
    }
    /// Consumes the builder and constructs a [`AwsEcsTaskDetails`](crate::types::AwsEcsTaskDetails).
    pub fn build(self) -> crate::types::AwsEcsTaskDetails {
        crate::types::AwsEcsTaskDetails {
            cluster_arn: self.cluster_arn,
            task_definition_arn: self.task_definition_arn,
            version: self.version,
            created_at: self.created_at,
            started_at: self.started_at,
            started_by: self.started_by,
            group: self.group,
            volumes: self.volumes,
            containers: self.containers,
        }
    }
}
