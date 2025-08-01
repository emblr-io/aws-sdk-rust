// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The state of a run of a condition for a stage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StageConditionState {
    /// <p>Represents information about the latest run of a condition for a stage.</p>
    pub latest_execution: ::std::option::Option<crate::types::StageConditionsExecution>,
    /// <p>The states of the conditions for a run of a condition for a stage.</p>
    pub condition_states: ::std::option::Option<::std::vec::Vec<crate::types::ConditionState>>,
}
impl StageConditionState {
    /// <p>Represents information about the latest run of a condition for a stage.</p>
    pub fn latest_execution(&self) -> ::std::option::Option<&crate::types::StageConditionsExecution> {
        self.latest_execution.as_ref()
    }
    /// <p>The states of the conditions for a run of a condition for a stage.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.condition_states.is_none()`.
    pub fn condition_states(&self) -> &[crate::types::ConditionState] {
        self.condition_states.as_deref().unwrap_or_default()
    }
}
impl StageConditionState {
    /// Creates a new builder-style object to manufacture [`StageConditionState`](crate::types::StageConditionState).
    pub fn builder() -> crate::types::builders::StageConditionStateBuilder {
        crate::types::builders::StageConditionStateBuilder::default()
    }
}

/// A builder for [`StageConditionState`](crate::types::StageConditionState).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StageConditionStateBuilder {
    pub(crate) latest_execution: ::std::option::Option<crate::types::StageConditionsExecution>,
    pub(crate) condition_states: ::std::option::Option<::std::vec::Vec<crate::types::ConditionState>>,
}
impl StageConditionStateBuilder {
    /// <p>Represents information about the latest run of a condition for a stage.</p>
    pub fn latest_execution(mut self, input: crate::types::StageConditionsExecution) -> Self {
        self.latest_execution = ::std::option::Option::Some(input);
        self
    }
    /// <p>Represents information about the latest run of a condition for a stage.</p>
    pub fn set_latest_execution(mut self, input: ::std::option::Option<crate::types::StageConditionsExecution>) -> Self {
        self.latest_execution = input;
        self
    }
    /// <p>Represents information about the latest run of a condition for a stage.</p>
    pub fn get_latest_execution(&self) -> &::std::option::Option<crate::types::StageConditionsExecution> {
        &self.latest_execution
    }
    /// Appends an item to `condition_states`.
    ///
    /// To override the contents of this collection use [`set_condition_states`](Self::set_condition_states).
    ///
    /// <p>The states of the conditions for a run of a condition for a stage.</p>
    pub fn condition_states(mut self, input: crate::types::ConditionState) -> Self {
        let mut v = self.condition_states.unwrap_or_default();
        v.push(input);
        self.condition_states = ::std::option::Option::Some(v);
        self
    }
    /// <p>The states of the conditions for a run of a condition for a stage.</p>
    pub fn set_condition_states(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConditionState>>) -> Self {
        self.condition_states = input;
        self
    }
    /// <p>The states of the conditions for a run of a condition for a stage.</p>
    pub fn get_condition_states(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConditionState>> {
        &self.condition_states
    }
    /// Consumes the builder and constructs a [`StageConditionState`](crate::types::StageConditionState).
    pub fn build(self) -> crate::types::StageConditionState {
        crate::types::StageConditionState {
            latest_execution: self.latest_execution,
            condition_states: self.condition_states,
        }
    }
}
