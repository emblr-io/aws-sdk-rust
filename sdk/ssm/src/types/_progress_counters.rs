// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An aggregate of step execution statuses displayed in the Amazon Web Services Systems Manager console for a multi-Region and multi-account Automation execution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProgressCounters {
    /// <p>The total number of steps run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub total_steps: i32,
    /// <p>The total number of steps that successfully completed in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub success_steps: i32,
    /// <p>The total number of steps that failed to run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub failed_steps: i32,
    /// <p>The total number of steps that the system cancelled in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub cancelled_steps: i32,
    /// <p>The total number of steps that timed out in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub timed_out_steps: i32,
}
impl ProgressCounters {
    /// <p>The total number of steps run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn total_steps(&self) -> i32 {
        self.total_steps
    }
    /// <p>The total number of steps that successfully completed in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn success_steps(&self) -> i32 {
        self.success_steps
    }
    /// <p>The total number of steps that failed to run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn failed_steps(&self) -> i32 {
        self.failed_steps
    }
    /// <p>The total number of steps that the system cancelled in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn cancelled_steps(&self) -> i32 {
        self.cancelled_steps
    }
    /// <p>The total number of steps that timed out in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn timed_out_steps(&self) -> i32 {
        self.timed_out_steps
    }
}
impl ProgressCounters {
    /// Creates a new builder-style object to manufacture [`ProgressCounters`](crate::types::ProgressCounters).
    pub fn builder() -> crate::types::builders::ProgressCountersBuilder {
        crate::types::builders::ProgressCountersBuilder::default()
    }
}

/// A builder for [`ProgressCounters`](crate::types::ProgressCounters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProgressCountersBuilder {
    pub(crate) total_steps: ::std::option::Option<i32>,
    pub(crate) success_steps: ::std::option::Option<i32>,
    pub(crate) failed_steps: ::std::option::Option<i32>,
    pub(crate) cancelled_steps: ::std::option::Option<i32>,
    pub(crate) timed_out_steps: ::std::option::Option<i32>,
}
impl ProgressCountersBuilder {
    /// <p>The total number of steps run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn total_steps(mut self, input: i32) -> Self {
        self.total_steps = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of steps run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn set_total_steps(mut self, input: ::std::option::Option<i32>) -> Self {
        self.total_steps = input;
        self
    }
    /// <p>The total number of steps run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn get_total_steps(&self) -> &::std::option::Option<i32> {
        &self.total_steps
    }
    /// <p>The total number of steps that successfully completed in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn success_steps(mut self, input: i32) -> Self {
        self.success_steps = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of steps that successfully completed in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn set_success_steps(mut self, input: ::std::option::Option<i32>) -> Self {
        self.success_steps = input;
        self
    }
    /// <p>The total number of steps that successfully completed in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn get_success_steps(&self) -> &::std::option::Option<i32> {
        &self.success_steps
    }
    /// <p>The total number of steps that failed to run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn failed_steps(mut self, input: i32) -> Self {
        self.failed_steps = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of steps that failed to run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn set_failed_steps(mut self, input: ::std::option::Option<i32>) -> Self {
        self.failed_steps = input;
        self
    }
    /// <p>The total number of steps that failed to run in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn get_failed_steps(&self) -> &::std::option::Option<i32> {
        &self.failed_steps
    }
    /// <p>The total number of steps that the system cancelled in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn cancelled_steps(mut self, input: i32) -> Self {
        self.cancelled_steps = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of steps that the system cancelled in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn set_cancelled_steps(mut self, input: ::std::option::Option<i32>) -> Self {
        self.cancelled_steps = input;
        self
    }
    /// <p>The total number of steps that the system cancelled in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn get_cancelled_steps(&self) -> &::std::option::Option<i32> {
        &self.cancelled_steps
    }
    /// <p>The total number of steps that timed out in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn timed_out_steps(mut self, input: i32) -> Self {
        self.timed_out_steps = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of steps that timed out in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn set_timed_out_steps(mut self, input: ::std::option::Option<i32>) -> Self {
        self.timed_out_steps = input;
        self
    }
    /// <p>The total number of steps that timed out in all specified Amazon Web Services Regions and Amazon Web Services accounts for the current Automation execution.</p>
    pub fn get_timed_out_steps(&self) -> &::std::option::Option<i32> {
        &self.timed_out_steps
    }
    /// Consumes the builder and constructs a [`ProgressCounters`](crate::types::ProgressCounters).
    pub fn build(self) -> crate::types::ProgressCounters {
        crate::types::ProgressCounters {
            total_steps: self.total_steps.unwrap_or_default(),
            success_steps: self.success_steps.unwrap_or_default(),
            failed_steps: self.failed_steps.unwrap_or_default(),
            cancelled_steps: self.cancelled_steps.unwrap_or_default(),
            timed_out_steps: self.timed_out_steps.unwrap_or_default(),
        }
    }
}
