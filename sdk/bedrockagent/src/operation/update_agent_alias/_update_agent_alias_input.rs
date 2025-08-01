// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAgentAliasInput {
    /// <p>The unique identifier of the agent.</p>
    pub agent_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the alias.</p>
    pub agent_alias_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a new name for the alias.</p>
    pub agent_alias_name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a new description for the alias.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Contains details about the routing configuration of the alias.</p>
    pub routing_configuration: ::std::option::Option<::std::vec::Vec<crate::types::AgentAliasRoutingConfigurationListItem>>,
    /// <p>The invocation state for the agent alias. To pause the agent alias, set the value to <code>REJECT_INVOCATIONS</code>. To start the agent alias running again, set the value to <code>ACCEPT_INVOCATIONS</code>. Use the <code>GetAgentAlias</code>, or <code>ListAgentAliases</code>, operation to get the invocation state of an agent alias.</p>
    pub alias_invocation_state: ::std::option::Option<crate::types::AliasInvocationState>,
}
impl UpdateAgentAliasInput {
    /// <p>The unique identifier of the agent.</p>
    pub fn agent_id(&self) -> ::std::option::Option<&str> {
        self.agent_id.as_deref()
    }
    /// <p>The unique identifier of the alias.</p>
    pub fn agent_alias_id(&self) -> ::std::option::Option<&str> {
        self.agent_alias_id.as_deref()
    }
    /// <p>Specifies a new name for the alias.</p>
    pub fn agent_alias_name(&self) -> ::std::option::Option<&str> {
        self.agent_alias_name.as_deref()
    }
    /// <p>Specifies a new description for the alias.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Contains details about the routing configuration of the alias.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.routing_configuration.is_none()`.
    pub fn routing_configuration(&self) -> &[crate::types::AgentAliasRoutingConfigurationListItem] {
        self.routing_configuration.as_deref().unwrap_or_default()
    }
    /// <p>The invocation state for the agent alias. To pause the agent alias, set the value to <code>REJECT_INVOCATIONS</code>. To start the agent alias running again, set the value to <code>ACCEPT_INVOCATIONS</code>. Use the <code>GetAgentAlias</code>, or <code>ListAgentAliases</code>, operation to get the invocation state of an agent alias.</p>
    pub fn alias_invocation_state(&self) -> ::std::option::Option<&crate::types::AliasInvocationState> {
        self.alias_invocation_state.as_ref()
    }
}
impl UpdateAgentAliasInput {
    /// Creates a new builder-style object to manufacture [`UpdateAgentAliasInput`](crate::operation::update_agent_alias::UpdateAgentAliasInput).
    pub fn builder() -> crate::operation::update_agent_alias::builders::UpdateAgentAliasInputBuilder {
        crate::operation::update_agent_alias::builders::UpdateAgentAliasInputBuilder::default()
    }
}

/// A builder for [`UpdateAgentAliasInput`](crate::operation::update_agent_alias::UpdateAgentAliasInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAgentAliasInputBuilder {
    pub(crate) agent_id: ::std::option::Option<::std::string::String>,
    pub(crate) agent_alias_id: ::std::option::Option<::std::string::String>,
    pub(crate) agent_alias_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) routing_configuration: ::std::option::Option<::std::vec::Vec<crate::types::AgentAliasRoutingConfigurationListItem>>,
    pub(crate) alias_invocation_state: ::std::option::Option<crate::types::AliasInvocationState>,
}
impl UpdateAgentAliasInputBuilder {
    /// <p>The unique identifier of the agent.</p>
    /// This field is required.
    pub fn agent_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the agent.</p>
    pub fn set_agent_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_id = input;
        self
    }
    /// <p>The unique identifier of the agent.</p>
    pub fn get_agent_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_id
    }
    /// <p>The unique identifier of the alias.</p>
    /// This field is required.
    pub fn agent_alias_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_alias_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the alias.</p>
    pub fn set_agent_alias_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_alias_id = input;
        self
    }
    /// <p>The unique identifier of the alias.</p>
    pub fn get_agent_alias_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_alias_id
    }
    /// <p>Specifies a new name for the alias.</p>
    /// This field is required.
    pub fn agent_alias_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_alias_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a new name for the alias.</p>
    pub fn set_agent_alias_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_alias_name = input;
        self
    }
    /// <p>Specifies a new name for the alias.</p>
    pub fn get_agent_alias_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_alias_name
    }
    /// <p>Specifies a new description for the alias.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a new description for the alias.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Specifies a new description for the alias.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `routing_configuration`.
    ///
    /// To override the contents of this collection use [`set_routing_configuration`](Self::set_routing_configuration).
    ///
    /// <p>Contains details about the routing configuration of the alias.</p>
    pub fn routing_configuration(mut self, input: crate::types::AgentAliasRoutingConfigurationListItem) -> Self {
        let mut v = self.routing_configuration.unwrap_or_default();
        v.push(input);
        self.routing_configuration = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains details about the routing configuration of the alias.</p>
    pub fn set_routing_configuration(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AgentAliasRoutingConfigurationListItem>>,
    ) -> Self {
        self.routing_configuration = input;
        self
    }
    /// <p>Contains details about the routing configuration of the alias.</p>
    pub fn get_routing_configuration(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AgentAliasRoutingConfigurationListItem>> {
        &self.routing_configuration
    }
    /// <p>The invocation state for the agent alias. To pause the agent alias, set the value to <code>REJECT_INVOCATIONS</code>. To start the agent alias running again, set the value to <code>ACCEPT_INVOCATIONS</code>. Use the <code>GetAgentAlias</code>, or <code>ListAgentAliases</code>, operation to get the invocation state of an agent alias.</p>
    pub fn alias_invocation_state(mut self, input: crate::types::AliasInvocationState) -> Self {
        self.alias_invocation_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The invocation state for the agent alias. To pause the agent alias, set the value to <code>REJECT_INVOCATIONS</code>. To start the agent alias running again, set the value to <code>ACCEPT_INVOCATIONS</code>. Use the <code>GetAgentAlias</code>, or <code>ListAgentAliases</code>, operation to get the invocation state of an agent alias.</p>
    pub fn set_alias_invocation_state(mut self, input: ::std::option::Option<crate::types::AliasInvocationState>) -> Self {
        self.alias_invocation_state = input;
        self
    }
    /// <p>The invocation state for the agent alias. To pause the agent alias, set the value to <code>REJECT_INVOCATIONS</code>. To start the agent alias running again, set the value to <code>ACCEPT_INVOCATIONS</code>. Use the <code>GetAgentAlias</code>, or <code>ListAgentAliases</code>, operation to get the invocation state of an agent alias.</p>
    pub fn get_alias_invocation_state(&self) -> &::std::option::Option<crate::types::AliasInvocationState> {
        &self.alias_invocation_state
    }
    /// Consumes the builder and constructs a [`UpdateAgentAliasInput`](crate::operation::update_agent_alias::UpdateAgentAliasInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_agent_alias::UpdateAgentAliasInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_agent_alias::UpdateAgentAliasInput {
            agent_id: self.agent_id,
            agent_alias_id: self.agent_alias_id,
            agent_alias_name: self.agent_alias_name,
            description: self.description,
            routing_configuration: self.routing_configuration,
            alias_invocation_state: self.alias_invocation_state,
        })
    }
}
