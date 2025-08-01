// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Launch actions status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LaunchActionsStatus {
    /// <p>Time where the AWS Systems Manager was detected as running on the launched instance.</p>
    pub ssm_agent_discovery_datetime: ::std::option::Option<::std::string::String>,
    /// <p>List of post launch action status.</p>
    pub runs: ::std::option::Option<::std::vec::Vec<crate::types::LaunchActionRun>>,
}
impl LaunchActionsStatus {
    /// <p>Time where the AWS Systems Manager was detected as running on the launched instance.</p>
    pub fn ssm_agent_discovery_datetime(&self) -> ::std::option::Option<&str> {
        self.ssm_agent_discovery_datetime.as_deref()
    }
    /// <p>List of post launch action status.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.runs.is_none()`.
    pub fn runs(&self) -> &[crate::types::LaunchActionRun] {
        self.runs.as_deref().unwrap_or_default()
    }
}
impl LaunchActionsStatus {
    /// Creates a new builder-style object to manufacture [`LaunchActionsStatus`](crate::types::LaunchActionsStatus).
    pub fn builder() -> crate::types::builders::LaunchActionsStatusBuilder {
        crate::types::builders::LaunchActionsStatusBuilder::default()
    }
}

/// A builder for [`LaunchActionsStatus`](crate::types::LaunchActionsStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LaunchActionsStatusBuilder {
    pub(crate) ssm_agent_discovery_datetime: ::std::option::Option<::std::string::String>,
    pub(crate) runs: ::std::option::Option<::std::vec::Vec<crate::types::LaunchActionRun>>,
}
impl LaunchActionsStatusBuilder {
    /// <p>Time where the AWS Systems Manager was detected as running on the launched instance.</p>
    pub fn ssm_agent_discovery_datetime(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ssm_agent_discovery_datetime = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Time where the AWS Systems Manager was detected as running on the launched instance.</p>
    pub fn set_ssm_agent_discovery_datetime(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ssm_agent_discovery_datetime = input;
        self
    }
    /// <p>Time where the AWS Systems Manager was detected as running on the launched instance.</p>
    pub fn get_ssm_agent_discovery_datetime(&self) -> &::std::option::Option<::std::string::String> {
        &self.ssm_agent_discovery_datetime
    }
    /// Appends an item to `runs`.
    ///
    /// To override the contents of this collection use [`set_runs`](Self::set_runs).
    ///
    /// <p>List of post launch action status.</p>
    pub fn runs(mut self, input: crate::types::LaunchActionRun) -> Self {
        let mut v = self.runs.unwrap_or_default();
        v.push(input);
        self.runs = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of post launch action status.</p>
    pub fn set_runs(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LaunchActionRun>>) -> Self {
        self.runs = input;
        self
    }
    /// <p>List of post launch action status.</p>
    pub fn get_runs(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LaunchActionRun>> {
        &self.runs
    }
    /// Consumes the builder and constructs a [`LaunchActionsStatus`](crate::types::LaunchActionsStatus).
    pub fn build(self) -> crate::types::LaunchActionsStatus {
        crate::types::LaunchActionsStatus {
            ssm_agent_discovery_datetime: self.ssm_agent_discovery_datetime,
            runs: self.runs,
        }
    }
}
