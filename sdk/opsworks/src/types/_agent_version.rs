// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes an agent version.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AgentVersion {
    /// <p>The agent version.</p>
    pub version: ::std::option::Option<::std::string::String>,
    /// <p>The configuration manager.</p>
    pub configuration_manager: ::std::option::Option<crate::types::StackConfigurationManager>,
}
impl AgentVersion {
    /// <p>The agent version.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
    /// <p>The configuration manager.</p>
    pub fn configuration_manager(&self) -> ::std::option::Option<&crate::types::StackConfigurationManager> {
        self.configuration_manager.as_ref()
    }
}
impl AgentVersion {
    /// Creates a new builder-style object to manufacture [`AgentVersion`](crate::types::AgentVersion).
    pub fn builder() -> crate::types::builders::AgentVersionBuilder {
        crate::types::builders::AgentVersionBuilder::default()
    }
}

/// A builder for [`AgentVersion`](crate::types::AgentVersion).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AgentVersionBuilder {
    pub(crate) version: ::std::option::Option<::std::string::String>,
    pub(crate) configuration_manager: ::std::option::Option<crate::types::StackConfigurationManager>,
}
impl AgentVersionBuilder {
    /// <p>The agent version.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The agent version.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The agent version.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// <p>The configuration manager.</p>
    pub fn configuration_manager(mut self, input: crate::types::StackConfigurationManager) -> Self {
        self.configuration_manager = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration manager.</p>
    pub fn set_configuration_manager(mut self, input: ::std::option::Option<crate::types::StackConfigurationManager>) -> Self {
        self.configuration_manager = input;
        self
    }
    /// <p>The configuration manager.</p>
    pub fn get_configuration_manager(&self) -> &::std::option::Option<crate::types::StackConfigurationManager> {
        &self.configuration_manager
    }
    /// Consumes the builder and constructs a [`AgentVersion`](crate::types::AgentVersion).
    pub fn build(self) -> crate::types::AgentVersion {
        crate::types::AgentVersion {
            version: self.version,
            configuration_manager: self.configuration_manager,
        }
    }
}
