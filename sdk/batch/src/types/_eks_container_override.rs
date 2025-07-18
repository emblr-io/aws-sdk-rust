// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Object representing any Kubernetes overrides to a job definition that's used in a <a href="https://docs.aws.amazon.com/batch/latest/APIReference/API_SubmitJob.html">SubmitJob</a> API operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EksContainerOverride {
    /// <p>A pointer to the container that you want to override. The name must match a unique container name that you wish to override.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The override of the Docker image that's used to start the container.</p>
    pub image: ::std::option::Option<::std::string::String>,
    /// <p>The command to send to the container that overrides the default command from the Docker image or the job definition.</p>
    pub command: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The arguments to the entrypoint to send to the container that overrides the default arguments from the Docker image or the job definition. For more information, see <a href="https://docs.docker.com/engine/reference/builder/#cmd">Dockerfile reference: CMD</a> and <a href="https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/">Define a command an arguments for a pod</a> in the <i>Kubernetes documentation</i>.</p>
    pub args: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The environment variables to send to the container. You can add new environment variables, which are added to the container at launch. Or, you can override the existing environment variables from the Docker image or the job definition.</p><note>
    /// <p>Environment variables cannot start with "<code>AWS_BATCH</code>". This naming convention is reserved for variables that Batch sets.</p>
    /// </note>
    pub env: ::std::option::Option<::std::vec::Vec<crate::types::EksContainerEnvironmentVariable>>,
    /// <p>The type and amount of resources to assign to a container. These override the settings in the job definition. The supported resources include <code>memory</code>, <code>cpu</code>, and <code>nvidia.com/gpu</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/">Resource management for pods and containers</a> in the <i>Kubernetes documentation</i>.</p>
    pub resources: ::std::option::Option<crate::types::EksContainerResourceRequirements>,
}
impl EksContainerOverride {
    /// <p>A pointer to the container that you want to override. The name must match a unique container name that you wish to override.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The override of the Docker image that's used to start the container.</p>
    pub fn image(&self) -> ::std::option::Option<&str> {
        self.image.as_deref()
    }
    /// <p>The command to send to the container that overrides the default command from the Docker image or the job definition.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.command.is_none()`.
    pub fn command(&self) -> &[::std::string::String] {
        self.command.as_deref().unwrap_or_default()
    }
    /// <p>The arguments to the entrypoint to send to the container that overrides the default arguments from the Docker image or the job definition. For more information, see <a href="https://docs.docker.com/engine/reference/builder/#cmd">Dockerfile reference: CMD</a> and <a href="https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/">Define a command an arguments for a pod</a> in the <i>Kubernetes documentation</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.args.is_none()`.
    pub fn args(&self) -> &[::std::string::String] {
        self.args.as_deref().unwrap_or_default()
    }
    /// <p>The environment variables to send to the container. You can add new environment variables, which are added to the container at launch. Or, you can override the existing environment variables from the Docker image or the job definition.</p><note>
    /// <p>Environment variables cannot start with "<code>AWS_BATCH</code>". This naming convention is reserved for variables that Batch sets.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.env.is_none()`.
    pub fn env(&self) -> &[crate::types::EksContainerEnvironmentVariable] {
        self.env.as_deref().unwrap_or_default()
    }
    /// <p>The type and amount of resources to assign to a container. These override the settings in the job definition. The supported resources include <code>memory</code>, <code>cpu</code>, and <code>nvidia.com/gpu</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/">Resource management for pods and containers</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn resources(&self) -> ::std::option::Option<&crate::types::EksContainerResourceRequirements> {
        self.resources.as_ref()
    }
}
impl EksContainerOverride {
    /// Creates a new builder-style object to manufacture [`EksContainerOverride`](crate::types::EksContainerOverride).
    pub fn builder() -> crate::types::builders::EksContainerOverrideBuilder {
        crate::types::builders::EksContainerOverrideBuilder::default()
    }
}

/// A builder for [`EksContainerOverride`](crate::types::EksContainerOverride).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EksContainerOverrideBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) image: ::std::option::Option<::std::string::String>,
    pub(crate) command: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) args: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) env: ::std::option::Option<::std::vec::Vec<crate::types::EksContainerEnvironmentVariable>>,
    pub(crate) resources: ::std::option::Option<crate::types::EksContainerResourceRequirements>,
}
impl EksContainerOverrideBuilder {
    /// <p>A pointer to the container that you want to override. The name must match a unique container name that you wish to override.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A pointer to the container that you want to override. The name must match a unique container name that you wish to override.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A pointer to the container that you want to override. The name must match a unique container name that you wish to override.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The override of the Docker image that's used to start the container.</p>
    pub fn image(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The override of the Docker image that's used to start the container.</p>
    pub fn set_image(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image = input;
        self
    }
    /// <p>The override of the Docker image that's used to start the container.</p>
    pub fn get_image(&self) -> &::std::option::Option<::std::string::String> {
        &self.image
    }
    /// Appends an item to `command`.
    ///
    /// To override the contents of this collection use [`set_command`](Self::set_command).
    ///
    /// <p>The command to send to the container that overrides the default command from the Docker image or the job definition.</p>
    pub fn command(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.command.unwrap_or_default();
        v.push(input.into());
        self.command = ::std::option::Option::Some(v);
        self
    }
    /// <p>The command to send to the container that overrides the default command from the Docker image or the job definition.</p>
    pub fn set_command(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.command = input;
        self
    }
    /// <p>The command to send to the container that overrides the default command from the Docker image or the job definition.</p>
    pub fn get_command(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.command
    }
    /// Appends an item to `args`.
    ///
    /// To override the contents of this collection use [`set_args`](Self::set_args).
    ///
    /// <p>The arguments to the entrypoint to send to the container that overrides the default arguments from the Docker image or the job definition. For more information, see <a href="https://docs.docker.com/engine/reference/builder/#cmd">Dockerfile reference: CMD</a> and <a href="https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/">Define a command an arguments for a pod</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn args(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.args.unwrap_or_default();
        v.push(input.into());
        self.args = ::std::option::Option::Some(v);
        self
    }
    /// <p>The arguments to the entrypoint to send to the container that overrides the default arguments from the Docker image or the job definition. For more information, see <a href="https://docs.docker.com/engine/reference/builder/#cmd">Dockerfile reference: CMD</a> and <a href="https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/">Define a command an arguments for a pod</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn set_args(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.args = input;
        self
    }
    /// <p>The arguments to the entrypoint to send to the container that overrides the default arguments from the Docker image or the job definition. For more information, see <a href="https://docs.docker.com/engine/reference/builder/#cmd">Dockerfile reference: CMD</a> and <a href="https://kubernetes.io/docs/tasks/inject-data-application/define-command-argument-container/">Define a command an arguments for a pod</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn get_args(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.args
    }
    /// Appends an item to `env`.
    ///
    /// To override the contents of this collection use [`set_env`](Self::set_env).
    ///
    /// <p>The environment variables to send to the container. You can add new environment variables, which are added to the container at launch. Or, you can override the existing environment variables from the Docker image or the job definition.</p><note>
    /// <p>Environment variables cannot start with "<code>AWS_BATCH</code>". This naming convention is reserved for variables that Batch sets.</p>
    /// </note>
    pub fn env(mut self, input: crate::types::EksContainerEnvironmentVariable) -> Self {
        let mut v = self.env.unwrap_or_default();
        v.push(input);
        self.env = ::std::option::Option::Some(v);
        self
    }
    /// <p>The environment variables to send to the container. You can add new environment variables, which are added to the container at launch. Or, you can override the existing environment variables from the Docker image or the job definition.</p><note>
    /// <p>Environment variables cannot start with "<code>AWS_BATCH</code>". This naming convention is reserved for variables that Batch sets.</p>
    /// </note>
    pub fn set_env(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EksContainerEnvironmentVariable>>) -> Self {
        self.env = input;
        self
    }
    /// <p>The environment variables to send to the container. You can add new environment variables, which are added to the container at launch. Or, you can override the existing environment variables from the Docker image or the job definition.</p><note>
    /// <p>Environment variables cannot start with "<code>AWS_BATCH</code>". This naming convention is reserved for variables that Batch sets.</p>
    /// </note>
    pub fn get_env(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EksContainerEnvironmentVariable>> {
        &self.env
    }
    /// <p>The type and amount of resources to assign to a container. These override the settings in the job definition. The supported resources include <code>memory</code>, <code>cpu</code>, and <code>nvidia.com/gpu</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/">Resource management for pods and containers</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn resources(mut self, input: crate::types::EksContainerResourceRequirements) -> Self {
        self.resources = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type and amount of resources to assign to a container. These override the settings in the job definition. The supported resources include <code>memory</code>, <code>cpu</code>, and <code>nvidia.com/gpu</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/">Resource management for pods and containers</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn set_resources(mut self, input: ::std::option::Option<crate::types::EksContainerResourceRequirements>) -> Self {
        self.resources = input;
        self
    }
    /// <p>The type and amount of resources to assign to a container. These override the settings in the job definition. The supported resources include <code>memory</code>, <code>cpu</code>, and <code>nvidia.com/gpu</code>. For more information, see <a href="https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/">Resource management for pods and containers</a> in the <i>Kubernetes documentation</i>.</p>
    pub fn get_resources(&self) -> &::std::option::Option<crate::types::EksContainerResourceRequirements> {
        &self.resources
    }
    /// Consumes the builder and constructs a [`EksContainerOverride`](crate::types::EksContainerOverride).
    pub fn build(self) -> crate::types::EksContainerOverride {
        crate::types::EksContainerOverride {
            name: self.name,
            image: self.image,
            command: self.command,
            args: self.args,
            env: self.env,
            resources: self.resources,
        }
    }
}
