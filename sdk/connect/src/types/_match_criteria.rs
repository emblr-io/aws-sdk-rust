// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object to define AgentsCriteria.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MatchCriteria {
    /// <p>An object to define agentIds.</p>
    pub agents_criteria: ::std::option::Option<crate::types::AgentsCriteria>,
}
impl MatchCriteria {
    /// <p>An object to define agentIds.</p>
    pub fn agents_criteria(&self) -> ::std::option::Option<&crate::types::AgentsCriteria> {
        self.agents_criteria.as_ref()
    }
}
impl MatchCriteria {
    /// Creates a new builder-style object to manufacture [`MatchCriteria`](crate::types::MatchCriteria).
    pub fn builder() -> crate::types::builders::MatchCriteriaBuilder {
        crate::types::builders::MatchCriteriaBuilder::default()
    }
}

/// A builder for [`MatchCriteria`](crate::types::MatchCriteria).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MatchCriteriaBuilder {
    pub(crate) agents_criteria: ::std::option::Option<crate::types::AgentsCriteria>,
}
impl MatchCriteriaBuilder {
    /// <p>An object to define agentIds.</p>
    pub fn agents_criteria(mut self, input: crate::types::AgentsCriteria) -> Self {
        self.agents_criteria = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object to define agentIds.</p>
    pub fn set_agents_criteria(mut self, input: ::std::option::Option<crate::types::AgentsCriteria>) -> Self {
        self.agents_criteria = input;
        self
    }
    /// <p>An object to define agentIds.</p>
    pub fn get_agents_criteria(&self) -> &::std::option::Option<crate::types::AgentsCriteria> {
        &self.agents_criteria
    }
    /// Consumes the builder and constructs a [`MatchCriteria`](crate::types::MatchCriteria).
    pub fn build(self) -> crate::types::MatchCriteria {
        crate::types::MatchCriteria {
            agents_criteria: self.agents_criteria,
        }
    }
}
