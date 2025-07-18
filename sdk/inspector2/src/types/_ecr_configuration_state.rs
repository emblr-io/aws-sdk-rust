// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about the state of the ECR scans for your environment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EcrConfigurationState {
    /// <p>An object that contains details about the state of the ECR re-scan settings.</p>
    pub rescan_duration_state: ::std::option::Option<crate::types::EcrRescanDurationState>,
}
impl EcrConfigurationState {
    /// <p>An object that contains details about the state of the ECR re-scan settings.</p>
    pub fn rescan_duration_state(&self) -> ::std::option::Option<&crate::types::EcrRescanDurationState> {
        self.rescan_duration_state.as_ref()
    }
}
impl EcrConfigurationState {
    /// Creates a new builder-style object to manufacture [`EcrConfigurationState`](crate::types::EcrConfigurationState).
    pub fn builder() -> crate::types::builders::EcrConfigurationStateBuilder {
        crate::types::builders::EcrConfigurationStateBuilder::default()
    }
}

/// A builder for [`EcrConfigurationState`](crate::types::EcrConfigurationState).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EcrConfigurationStateBuilder {
    pub(crate) rescan_duration_state: ::std::option::Option<crate::types::EcrRescanDurationState>,
}
impl EcrConfigurationStateBuilder {
    /// <p>An object that contains details about the state of the ECR re-scan settings.</p>
    pub fn rescan_duration_state(mut self, input: crate::types::EcrRescanDurationState) -> Self {
        self.rescan_duration_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains details about the state of the ECR re-scan settings.</p>
    pub fn set_rescan_duration_state(mut self, input: ::std::option::Option<crate::types::EcrRescanDurationState>) -> Self {
        self.rescan_duration_state = input;
        self
    }
    /// <p>An object that contains details about the state of the ECR re-scan settings.</p>
    pub fn get_rescan_duration_state(&self) -> &::std::option::Option<crate::types::EcrRescanDurationState> {
        &self.rescan_duration_state
    }
    /// Consumes the builder and constructs a [`EcrConfigurationState`](crate::types::EcrConfigurationState).
    pub fn build(self) -> crate::types::EcrConfigurationState {
        crate::types::EcrConfigurationState {
            rescan_duration_state: self.rescan_duration_state,
        }
    }
}
