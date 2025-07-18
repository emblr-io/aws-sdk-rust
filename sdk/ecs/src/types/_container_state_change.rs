// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object that represents a change in state for a container.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContainerStateChange {
    /// <p>The name of the container.</p>
    pub container_name: ::std::option::Option<::std::string::String>,
    /// <p>The container image SHA 256 digest.</p>
    pub image_digest: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the Docker container.</p>
    pub runtime_id: ::std::option::Option<::std::string::String>,
    /// <p>The exit code for the container, if the state change is a result of the container exiting.</p>
    pub exit_code: ::std::option::Option<i32>,
    /// <p>Any network bindings that are associated with the container.</p>
    pub network_bindings: ::std::option::Option<::std::vec::Vec<crate::types::NetworkBinding>>,
    /// <p>The reason for the state change.</p>
    pub reason: ::std::option::Option<::std::string::String>,
    /// <p>The status of the container.</p>
    pub status: ::std::option::Option<::std::string::String>,
}
impl ContainerStateChange {
    /// <p>The name of the container.</p>
    pub fn container_name(&self) -> ::std::option::Option<&str> {
        self.container_name.as_deref()
    }
    /// <p>The container image SHA 256 digest.</p>
    pub fn image_digest(&self) -> ::std::option::Option<&str> {
        self.image_digest.as_deref()
    }
    /// <p>The ID of the Docker container.</p>
    pub fn runtime_id(&self) -> ::std::option::Option<&str> {
        self.runtime_id.as_deref()
    }
    /// <p>The exit code for the container, if the state change is a result of the container exiting.</p>
    pub fn exit_code(&self) -> ::std::option::Option<i32> {
        self.exit_code
    }
    /// <p>Any network bindings that are associated with the container.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.network_bindings.is_none()`.
    pub fn network_bindings(&self) -> &[crate::types::NetworkBinding] {
        self.network_bindings.as_deref().unwrap_or_default()
    }
    /// <p>The reason for the state change.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
    /// <p>The status of the container.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
}
impl ContainerStateChange {
    /// Creates a new builder-style object to manufacture [`ContainerStateChange`](crate::types::ContainerStateChange).
    pub fn builder() -> crate::types::builders::ContainerStateChangeBuilder {
        crate::types::builders::ContainerStateChangeBuilder::default()
    }
}

/// A builder for [`ContainerStateChange`](crate::types::ContainerStateChange).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContainerStateChangeBuilder {
    pub(crate) container_name: ::std::option::Option<::std::string::String>,
    pub(crate) image_digest: ::std::option::Option<::std::string::String>,
    pub(crate) runtime_id: ::std::option::Option<::std::string::String>,
    pub(crate) exit_code: ::std::option::Option<i32>,
    pub(crate) network_bindings: ::std::option::Option<::std::vec::Vec<crate::types::NetworkBinding>>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
}
impl ContainerStateChangeBuilder {
    /// <p>The name of the container.</p>
    pub fn container_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container.</p>
    pub fn set_container_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_name = input;
        self
    }
    /// <p>The name of the container.</p>
    pub fn get_container_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_name
    }
    /// <p>The container image SHA 256 digest.</p>
    pub fn image_digest(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.image_digest = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The container image SHA 256 digest.</p>
    pub fn set_image_digest(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.image_digest = input;
        self
    }
    /// <p>The container image SHA 256 digest.</p>
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
    /// <p>The exit code for the container, if the state change is a result of the container exiting.</p>
    pub fn exit_code(mut self, input: i32) -> Self {
        self.exit_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The exit code for the container, if the state change is a result of the container exiting.</p>
    pub fn set_exit_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.exit_code = input;
        self
    }
    /// <p>The exit code for the container, if the state change is a result of the container exiting.</p>
    pub fn get_exit_code(&self) -> &::std::option::Option<i32> {
        &self.exit_code
    }
    /// Appends an item to `network_bindings`.
    ///
    /// To override the contents of this collection use [`set_network_bindings`](Self::set_network_bindings).
    ///
    /// <p>Any network bindings that are associated with the container.</p>
    pub fn network_bindings(mut self, input: crate::types::NetworkBinding) -> Self {
        let mut v = self.network_bindings.unwrap_or_default();
        v.push(input);
        self.network_bindings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Any network bindings that are associated with the container.</p>
    pub fn set_network_bindings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::NetworkBinding>>) -> Self {
        self.network_bindings = input;
        self
    }
    /// <p>Any network bindings that are associated with the container.</p>
    pub fn get_network_bindings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::NetworkBinding>> {
        &self.network_bindings
    }
    /// <p>The reason for the state change.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason for the state change.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason for the state change.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// <p>The status of the container.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the container.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the container.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// Consumes the builder and constructs a [`ContainerStateChange`](crate::types::ContainerStateChange).
    pub fn build(self) -> crate::types::ContainerStateChange {
        crate::types::ContainerStateChange {
            container_name: self.container_name,
            image_digest: self.image_digest,
            runtime_id: self.runtime_id,
            exit_code: self.exit_code,
            network_bindings: self.network_bindings,
            reason: self.reason,
            status: self.status,
        }
    }
}
