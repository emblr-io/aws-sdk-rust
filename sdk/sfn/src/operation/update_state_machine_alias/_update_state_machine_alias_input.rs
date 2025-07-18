// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateStateMachineAliasInput {
    /// <p>The Amazon Resource Name (ARN) of the state machine alias.</p>
    pub state_machine_alias_arn: ::std::option::Option<::std::string::String>,
    /// <p>A description of the state machine alias.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The routing configuration of the state machine alias.</p>
    /// <p>An array of <code>RoutingConfig</code> objects that specifies up to two state machine versions that the alias starts executions for.</p>
    pub routing_configuration: ::std::option::Option<::std::vec::Vec<crate::types::RoutingConfigurationListItem>>,
}
impl UpdateStateMachineAliasInput {
    /// <p>The Amazon Resource Name (ARN) of the state machine alias.</p>
    pub fn state_machine_alias_arn(&self) -> ::std::option::Option<&str> {
        self.state_machine_alias_arn.as_deref()
    }
    /// <p>A description of the state machine alias.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The routing configuration of the state machine alias.</p>
    /// <p>An array of <code>RoutingConfig</code> objects that specifies up to two state machine versions that the alias starts executions for.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.routing_configuration.is_none()`.
    pub fn routing_configuration(&self) -> &[crate::types::RoutingConfigurationListItem] {
        self.routing_configuration.as_deref().unwrap_or_default()
    }
}
impl ::std::fmt::Debug for UpdateStateMachineAliasInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateStateMachineAliasInput");
        formatter.field("state_machine_alias_arn", &self.state_machine_alias_arn);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("routing_configuration", &self.routing_configuration);
        formatter.finish()
    }
}
impl UpdateStateMachineAliasInput {
    /// Creates a new builder-style object to manufacture [`UpdateStateMachineAliasInput`](crate::operation::update_state_machine_alias::UpdateStateMachineAliasInput).
    pub fn builder() -> crate::operation::update_state_machine_alias::builders::UpdateStateMachineAliasInputBuilder {
        crate::operation::update_state_machine_alias::builders::UpdateStateMachineAliasInputBuilder::default()
    }
}

/// A builder for [`UpdateStateMachineAliasInput`](crate::operation::update_state_machine_alias::UpdateStateMachineAliasInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateStateMachineAliasInputBuilder {
    pub(crate) state_machine_alias_arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) routing_configuration: ::std::option::Option<::std::vec::Vec<crate::types::RoutingConfigurationListItem>>,
}
impl UpdateStateMachineAliasInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the state machine alias.</p>
    /// This field is required.
    pub fn state_machine_alias_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state_machine_alias_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the state machine alias.</p>
    pub fn set_state_machine_alias_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state_machine_alias_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the state machine alias.</p>
    pub fn get_state_machine_alias_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.state_machine_alias_arn
    }
    /// <p>A description of the state machine alias.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the state machine alias.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the state machine alias.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `routing_configuration`.
    ///
    /// To override the contents of this collection use [`set_routing_configuration`](Self::set_routing_configuration).
    ///
    /// <p>The routing configuration of the state machine alias.</p>
    /// <p>An array of <code>RoutingConfig</code> objects that specifies up to two state machine versions that the alias starts executions for.</p>
    pub fn routing_configuration(mut self, input: crate::types::RoutingConfigurationListItem) -> Self {
        let mut v = self.routing_configuration.unwrap_or_default();
        v.push(input);
        self.routing_configuration = ::std::option::Option::Some(v);
        self
    }
    /// <p>The routing configuration of the state machine alias.</p>
    /// <p>An array of <code>RoutingConfig</code> objects that specifies up to two state machine versions that the alias starts executions for.</p>
    pub fn set_routing_configuration(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RoutingConfigurationListItem>>) -> Self {
        self.routing_configuration = input;
        self
    }
    /// <p>The routing configuration of the state machine alias.</p>
    /// <p>An array of <code>RoutingConfig</code> objects that specifies up to two state machine versions that the alias starts executions for.</p>
    pub fn get_routing_configuration(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RoutingConfigurationListItem>> {
        &self.routing_configuration
    }
    /// Consumes the builder and constructs a [`UpdateStateMachineAliasInput`](crate::operation::update_state_machine_alias::UpdateStateMachineAliasInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_state_machine_alias::UpdateStateMachineAliasInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_state_machine_alias::UpdateStateMachineAliasInput {
            state_machine_alias_arn: self.state_machine_alias_arn,
            description: self.description,
            routing_configuration: self.routing_configuration,
        })
    }
}
impl ::std::fmt::Debug for UpdateStateMachineAliasInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateStateMachineAliasInputBuilder");
        formatter.field("state_machine_alias_arn", &self.state_machine_alias_arn);
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("routing_configuration", &self.routing_configuration);
        formatter.finish()
    }
}
