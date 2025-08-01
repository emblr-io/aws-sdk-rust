// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateAgentAliasOutput {
    /// <p>Contains details about the alias that was created.</p>
    pub agent_alias: ::std::option::Option<crate::types::AgentAlias>,
    _request_id: Option<String>,
}
impl CreateAgentAliasOutput {
    /// <p>Contains details about the alias that was created.</p>
    pub fn agent_alias(&self) -> ::std::option::Option<&crate::types::AgentAlias> {
        self.agent_alias.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateAgentAliasOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateAgentAliasOutput {
    /// Creates a new builder-style object to manufacture [`CreateAgentAliasOutput`](crate::operation::create_agent_alias::CreateAgentAliasOutput).
    pub fn builder() -> crate::operation::create_agent_alias::builders::CreateAgentAliasOutputBuilder {
        crate::operation::create_agent_alias::builders::CreateAgentAliasOutputBuilder::default()
    }
}

/// A builder for [`CreateAgentAliasOutput`](crate::operation::create_agent_alias::CreateAgentAliasOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateAgentAliasOutputBuilder {
    pub(crate) agent_alias: ::std::option::Option<crate::types::AgentAlias>,
    _request_id: Option<String>,
}
impl CreateAgentAliasOutputBuilder {
    /// <p>Contains details about the alias that was created.</p>
    /// This field is required.
    pub fn agent_alias(mut self, input: crate::types::AgentAlias) -> Self {
        self.agent_alias = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details about the alias that was created.</p>
    pub fn set_agent_alias(mut self, input: ::std::option::Option<crate::types::AgentAlias>) -> Self {
        self.agent_alias = input;
        self
    }
    /// <p>Contains details about the alias that was created.</p>
    pub fn get_agent_alias(&self) -> &::std::option::Option<crate::types::AgentAlias> {
        &self.agent_alias
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateAgentAliasOutput`](crate::operation::create_agent_alias::CreateAgentAliasOutput).
    pub fn build(self) -> crate::operation::create_agent_alias::CreateAgentAliasOutput {
        crate::operation::create_agent_alias::CreateAgentAliasOutput {
            agent_alias: self.agent_alias,
            _request_id: self._request_id,
        }
    }
}
