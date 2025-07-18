// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the status of the docker server.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DockerServerStatus {
    /// <p>The status of the docker server.</p>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>A message associated with the status of a docker server.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl DockerServerStatus {
    /// <p>The status of the docker server.</p>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>A message associated with the status of a docker server.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl DockerServerStatus {
    /// Creates a new builder-style object to manufacture [`DockerServerStatus`](crate::types::DockerServerStatus).
    pub fn builder() -> crate::types::builders::DockerServerStatusBuilder {
        crate::types::builders::DockerServerStatusBuilder::default()
    }
}

/// A builder for [`DockerServerStatus`](crate::types::DockerServerStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DockerServerStatusBuilder {
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl DockerServerStatusBuilder {
    /// <p>The status of the docker server.</p>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status of the docker server.</p>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the docker server.</p>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>A message associated with the status of a docker server.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message associated with the status of a docker server.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message associated with the status of a docker server.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`DockerServerStatus`](crate::types::DockerServerStatus).
    pub fn build(self) -> crate::types::DockerServerStatus {
        crate::types::DockerServerStatus {
            status: self.status,
            message: self.message,
        }
    }
}
