// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A Docker container that's part of a task.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Container {
    /// <p>The Amazon Resource Name (ARN) of the container.</p>
    pub container_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the task.</p>
    pub task_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the container.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The image used for the container.</p>
    pub image: ::std::option::Option<::std::string::String>,
    /// <p>The container image manifest digest.</p>
    pub image_digest: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Docker container.</p>
    pub runtime_id: ::std::option::Option<::std::string::String>,
    /// <p>The last known status of the container.</p>
    pub last_status: ::std::option::Option<::std::string::String>,
    /// <p>The exit code returned from the container.</p>
    pub exit_code: ::std::option::Option<i32>,
    /// <p>A short (1024 max characters) human-readable string to provide additional details about a running or stopped container.</p>
    pub reason: ::std::option::Option<::std::string::String>,
    /// <p>The network bindings associated with the container.</p>
    pub network_bindings: ::std::option::Option<::std::vec::Vec<crate::types::NetworkBinding>>,
    /// <p>The network interfaces associated with the container.</p>
    pub network_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::NetworkInterface>>,
    /// <p>The health status of the container. If health checks aren't configured for this container in its task definition, then it reports the health status as <code>UNKNOWN</code>.</p>
    pub health_status: ::std::option::Option<crate::types::HealthStatus>,
    /// <p>The details of any Amazon ECS managed agents associated with the container.</p>
    pub managed_agents: ::std::option::Option<::std::vec::Vec<crate::types::ManagedAgent>>,
    /// <p>The number of CPU units set for the container. The value is <code>0</code> if no value was specified in the container definition when the task definition was registered.</p>
    pub cpu: ::std::option::Option<::std::string::String>,
    /// <p>The hard limit (in MiB) of memory set for the container.</p>
    pub memory: ::std::option::Option<::std::string::String>,
    /// <p>The soft limit (in MiB) of memory set for the container.</p>
    pub memory_reservation: ::std::option::Option<::std::string::String>,
    /// <p>The IDs of each GPU assigned to the container.</p>
    pub gpu_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Container {
    /// <p>The Amazon Resource Name (ARN) of the container.</p>
    pub fn container_arn(&self) -> ::std::option::Option<&str> {
        self.container_arn.as_deref()
    }
    /// <p>The ARN of the task.</p>
    pub fn task_arn(&self) -> ::std::option::Option<&str> {
        self.task_arn.as_deref()
    }
    /// <p>The name of the container.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The image used for the container.</p>
    pub fn image(&self) -> ::std::option::Option<&str> {
        self.image.as_deref()
    }
    /// <p>The container image manifest digest.</p>
    pub fn image_digest(&self) -> ::std::option::Option<&str> {
        self.image_digest.as_deref()
    }
    /// <p>The ID of the Docker container.</p>
    pub fn runtime_id(&self) -> ::std::option::Option<&str> {
        self.runtime_id.as_deref()
    }
    /// <p>The last known status of the container.</p>
    pub fn last_status(&self) -> ::std::option::Option<&str> {
        self.last_status.as_deref()
    }
    /// <p>The exit code returned from the container.</p>
    pub fn exit_code(&self) -> ::std::option::Option<i32> {
        self.exit_code
    }
    /// <p>A short (1024 max characters) human-readable string to provide additional details about a running or stopped container.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
    /// <p>The network bindings associated with the container.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.network_bindings.is_none()`.
    pub fn network_bindings(&self) -> &[crate::types::NetworkBinding] {
        self.network_bindings.as_deref().unwrap_or_default()
    }
    /// <p>The network interfaces associated with the container.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.network_interfaces.is_none()`.
    pub fn network_interfaces(&self) -> &[crate::types::NetworkInterface] {
        self.network_interfaces.as_deref().unwrap_or_default()
    }
    /// <p>The health status of the container. If health checks aren't configured for this container in its task definition, then it reports the health status as <code>UNKNOWN</code>.</p>
    pub fn health_status(&self) -> ::std::option::Option<&crate::types::HealthStatus> {
        self.health_status.as_ref()
    }
    /// <p>The details of any Amazon ECS managed agents associated with the container.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.managed_agents.is_none()`.
    pub fn managed_agents(&self) -> &[crate::types::ManagedAgent] {
        self.managed_agents.as_deref().unwrap_or_default()
    }
    /// <p>The number of CPU units set for the container. The value is <code>0</code> if no value was specified in the container definition when the task definition was registered.</p>
    pub fn cpu(&self) -> ::std::option::Option<&str> {
        self.cpu.as_deref()
    }
    /// <p>The hard limit (in MiB) of memory set for the container.</p>
    pub fn memory(&self) -> ::std::option::Option<&str> {
        self.memory.as_deref()
    }
    /// <p>The soft limit (in MiB) of memory set for the container.</p>
    pub fn memory_reservation(&self) -> ::std::option::Option<&str> {
        self.memory_reservation.as_deref()
    }
    /// <p>The IDs of each GPU assigned to the container.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.gpu_ids.is_none()`.
    pub fn gpu_ids(&self) -> &[::std::string::String] {
        self.gpu_ids.as_deref().unwrap_or_default()
    }
}
impl Container {
    /// Creates a new builder-style object to manufacture [`Container`](crate::types::Container).
    pub fn builder() -> crate::types::builders::ContainerBuilder {
        crate::types::builders::ContainerBuilder::default()
    }
}

/// A builder for [`Container`](crate::types::Container).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContainerBuilder {
    pub(crate) container_arn: ::std::option::Option<::std::string::String>,
    pub(crate) task_arn: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) image: ::std::option::Option<::std::string::String>,
    pub(crate) image_digest: ::std::option::Option<::std::string::String>,
    pub(crate) runtime_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_status: ::std::option::Option<::std::string::String>,
    pub(crate) exit_code: ::std::option::Option<i32>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
    pub(crate) network_bindings: ::std::option::Option<::std::vec::Vec<crate::types::NetworkBinding>>,
    pub(crate) network_interfaces: ::std::option::Option<::std::vec::Vec<crate::types::NetworkInterface>>,
    pub(crate) health_status: ::std::option::Option<crate::types::HealthStatus>,
    pub(crate) managed_agents: ::std::option::Option<::std::vec::Vec<crate::types::ManagedAgent>>,
    pub(crate) cpu: ::std::option::Option<::std::string::String>,
    pub(crate) memory: ::std::option::Option<::std::string::String>,
    pub(crate) memory_reservation: ::std::option::Option<::std::string::String>,
    pub(crate) gpu_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ContainerBuilder {
    /// <p>The Amazon Resource Name (ARN) of the container.</p>
    pub fn container_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the container.</p>
    pub fn set_container_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the container.</p>
    pub fn get_container_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_arn
    }
    /// <p>The ARN of the task.</p>
    pub fn task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the task.</p>
    pub fn set_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_arn = input;
        self
    }
    /// <p>The ARN of the task.</p>
    pub fn get_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_arn
    }
    /// <p>The name of the container.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the container.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The image used for the container.</p>
    pub fn image(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The image used for the container.</p>
    pub fn set_image(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image = input;
        self
    }
    /// <p>The image used for the container.</p>
    pub fn get_image(&self) -> &::std::option::Option<::std::string::String> {
        &self.image
    }
    /// <p>The container image manifest digest.</p>
    pub fn image_digest(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_digest = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The container image manifest digest.</p>
    pub fn set_image_digest(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_digest = input;
        self
    }
    /// <p>The container image manifest digest.</p>
    pub fn get_image_digest(&self) -> &::std::option::Option<::std::string::String> {
        &self.image_digest
    }
    /// <p>The ID of the Docker container.</p>
    pub fn runtime_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.runtime_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Docker container.</p>
    pub fn set_runtime_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.runtime_id = input;
        self
    }
    /// <p>The ID of the Docker container.</p>
    pub fn get_runtime_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.runtime_id
    }
    /// <p>The last known status of the container.</p>
    pub fn last_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The last known status of the container.</p>
    pub fn set_last_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_status = input;
        self
    }
    /// <p>The last known status of the container.</p>
    pub fn get_last_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_status
    }
    /// <p>The exit code returned from the container.</p>
    pub fn exit_code(mut self, input: i32) -> Self {
        self.exit_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The exit code returned from the container.</p>
    pub fn set_exit_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.exit_code = input;
        self
    }
    /// <p>The exit code returned from the container.</p>
    pub fn get_exit_code(&self) -> &::std::option::Option<i32> {
        &self.exit_code
    }
    /// <p>A short (1024 max characters) human-readable string to provide additional details about a running or stopped container.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A short (1024 max characters) human-readable string to provide additional details about a running or stopped container.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>A short (1024 max characters) human-readable string to provide additional details about a running or stopped container.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// Appends an item to `network_bindings`.
    ///
    /// To override the contents of this collection use [`set_network_bindings`](Self::set_network_bindings).
    ///
    /// <p>The network bindings associated with the container.</p>
    pub fn network_bindings(mut self, input: crate::types::NetworkBinding) -> Self {
        let mut v = self.network_bindings.unwrap_or_default();
        v.push(input);
        self.network_bindings = ::std::option::Option::Some(v);
        self
    }
    /// <p>The network bindings associated with the container.</p>
    pub fn set_network_bindings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NetworkBinding>>) -> Self {
        self.network_bindings = input;
        self
    }
    /// <p>The network bindings associated with the container.</p>
    pub fn get_network_bindings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NetworkBinding>> {
        &self.network_bindings
    }
    /// Appends an item to `network_interfaces`.
    ///
    /// To override the contents of this collection use [`set_network_interfaces`](Self::set_network_interfaces).
    ///
    /// <p>The network interfaces associated with the container.</p>
    pub fn network_interfaces(mut self, input: crate::types::NetworkInterface) -> Self {
        let mut v = self.network_interfaces.unwrap_or_default();
        v.push(input);
        self.network_interfaces = ::std::option::Option::Some(v);
        self
    }
    /// <p>The network interfaces associated with the container.</p>
    pub fn set_network_interfaces(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NetworkInterface>>) -> Self {
        self.network_interfaces = input;
        self
    }
    /// <p>The network interfaces associated with the container.</p>
    pub fn get_network_interfaces(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NetworkInterface>> {
        &self.network_interfaces
    }
    /// <p>The health status of the container. If health checks aren't configured for this container in its task definition, then it reports the health status as <code>UNKNOWN</code>.</p>
    pub fn health_status(mut self, input: crate::types::HealthStatus) -> Self {
        self.health_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The health status of the container. If health checks aren't configured for this container in its task definition, then it reports the health status as <code>UNKNOWN</code>.</p>
    pub fn set_health_status(mut self, input: ::std::option::Option<crate::types::HealthStatus>) -> Self {
        self.health_status = input;
        self
    }
    /// <p>The health status of the container. If health checks aren't configured for this container in its task definition, then it reports the health status as <code>UNKNOWN</code>.</p>
    pub fn get_health_status(&self) -> &::std::option::Option<crate::types::HealthStatus> {
        &self.health_status
    }
    /// Appends an item to `managed_agents`.
    ///
    /// To override the contents of this collection use [`set_managed_agents`](Self::set_managed_agents).
    ///
    /// <p>The details of any Amazon ECS managed agents associated with the container.</p>
    pub fn managed_agents(mut self, input: crate::types::ManagedAgent) -> Self {
        let mut v = self.managed_agents.unwrap_or_default();
        v.push(input);
        self.managed_agents = ::std::option::Option::Some(v);
        self
    }
    /// <p>The details of any Amazon ECS managed agents associated with the container.</p>
    pub fn set_managed_agents(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ManagedAgent>>) -> Self {
        self.managed_agents = input;
        self
    }
    /// <p>The details of any Amazon ECS managed agents associated with the container.</p>
    pub fn get_managed_agents(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ManagedAgent>> {
        &self.managed_agents
    }
    /// <p>The number of CPU units set for the container. The value is <code>0</code> if no value was specified in the container definition when the task definition was registered.</p>
    pub fn cpu(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cpu = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The number of CPU units set for the container. The value is <code>0</code> if no value was specified in the container definition when the task definition was registered.</p>
    pub fn set_cpu(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cpu = input;
        self
    }
    /// <p>The number of CPU units set for the container. The value is <code>0</code> if no value was specified in the container definition when the task definition was registered.</p>
    pub fn get_cpu(&self) -> &::std::option::Option<::std::string::String> {
        &self.cpu
    }
    /// <p>The hard limit (in MiB) of memory set for the container.</p>
    pub fn memory(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.memory = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The hard limit (in MiB) of memory set for the container.</p>
    pub fn set_memory(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.memory = input;
        self
    }
    /// <p>The hard limit (in MiB) of memory set for the container.</p>
    pub fn get_memory(&self) -> &::std::option::Option<::std::string::String> {
        &self.memory
    }
    /// <p>The soft limit (in MiB) of memory set for the container.</p>
    pub fn memory_reservation(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.memory_reservation = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The soft limit (in MiB) of memory set for the container.</p>
    pub fn set_memory_reservation(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.memory_reservation = input;
        self
    }
    /// <p>The soft limit (in MiB) of memory set for the container.</p>
    pub fn get_memory_reservation(&self) -> &::std::option::Option<::std::string::String> {
        &self.memory_reservation
    }
    /// Appends an item to `gpu_ids`.
    ///
    /// To override the contents of this collection use [`set_gpu_ids`](Self::set_gpu_ids).
    ///
    /// <p>The IDs of each GPU assigned to the container.</p>
    pub fn gpu_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.gpu_ids.unwrap_or_default();
        v.push(input.into());
        self.gpu_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of each GPU assigned to the container.</p>
    pub fn set_gpu_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.gpu_ids = input;
        self
    }
    /// <p>The IDs of each GPU assigned to the container.</p>
    pub fn get_gpu_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.gpu_ids
    }
    /// Consumes the builder and constructs a [`Container`](crate::types::Container).
    pub fn build(self) -> crate::types::Container {
        crate::types::Container {
            container_arn: self.container_arn,
            task_arn: self.task_arn,
            name: self.name,
            image: self.image,
            image_digest: self.image_digest,
            runtime_id: self.runtime_id,
            last_status: self.last_status,
            exit_code: self.exit_code,
            reason: self.reason,
            network_bindings: self.network_bindings,
            network_interfaces: self.network_interfaces,
            health_status: self.health_status,
            managed_agents: self.managed_agents,
            cpu: self.cpu,
            memory: self.memory,
            memory_reservation: self.memory_reservation,
            gpu_ids: self.gpu_ids,
        }
    }
}
