// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about an instance refresh rollback.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RollbackDetails {
    /// <p>The reason for this instance refresh rollback (for example, whether a manual or automatic rollback was initiated).</p>
    pub rollback_reason: ::std::option::Option<::std::string::String>,
    /// <p>The date and time at which the rollback began.</p>
    pub rollback_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Indicates the value of <code>PercentageComplete</code> at the time the rollback started.</p>
    pub percentage_complete_on_rollback: ::std::option::Option<i32>,
    /// <p>Indicates the value of <code>InstancesToUpdate</code> at the time the rollback started.</p>
    pub instances_to_update_on_rollback: ::std::option::Option<i32>,
    /// <p>Reports progress on replacing instances in an Auto Scaling group that has a warm pool. This includes separate details for instances in the warm pool and instances in the Auto Scaling group (the live pool).</p>
    pub progress_details_on_rollback: ::std::option::Option<crate::types::InstanceRefreshProgressDetails>,
}
impl RollbackDetails {
    /// <p>The reason for this instance refresh rollback (for example, whether a manual or automatic rollback was initiated).</p>
    pub fn rollback_reason(&self) -> ::std::option::Option<&str> {
        self.rollback_reason.as_deref()
    }
    /// <p>The date and time at which the rollback began.</p>
    pub fn rollback_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.rollback_start_time.as_ref()
    }
    /// <p>Indicates the value of <code>PercentageComplete</code> at the time the rollback started.</p>
    pub fn percentage_complete_on_rollback(&self) -> ::std::option::Option<i32> {
        self.percentage_complete_on_rollback
    }
    /// <p>Indicates the value of <code>InstancesToUpdate</code> at the time the rollback started.</p>
    pub fn instances_to_update_on_rollback(&self) -> ::std::option::Option<i32> {
        self.instances_to_update_on_rollback
    }
    /// <p>Reports progress on replacing instances in an Auto Scaling group that has a warm pool. This includes separate details for instances in the warm pool and instances in the Auto Scaling group (the live pool).</p>
    pub fn progress_details_on_rollback(&self) -> ::std::option::Option<&crate::types::InstanceRefreshProgressDetails> {
        self.progress_details_on_rollback.as_ref()
    }
}
impl RollbackDetails {
    /// Creates a new builder-style object to manufacture [`RollbackDetails`](crate::types::RollbackDetails).
    pub fn builder() -> crate::types::builders::RollbackDetailsBuilder {
        crate::types::builders::RollbackDetailsBuilder::default()
    }
}

/// A builder for [`RollbackDetails`](crate::types::RollbackDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RollbackDetailsBuilder {
    pub(crate) rollback_reason: ::std::option::Option<::std::string::String>,
    pub(crate) rollback_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) percentage_complete_on_rollback: ::std::option::Option<i32>,
    pub(crate) instances_to_update_on_rollback: ::std::option::Option<i32>,
    pub(crate) progress_details_on_rollback: ::std::option::Option<crate::types::InstanceRefreshProgressDetails>,
}
impl RollbackDetailsBuilder {
    /// <p>The reason for this instance refresh rollback (for example, whether a manual or automatic rollback was initiated).</p>
    pub fn rollback_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.rollback_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason for this instance refresh rollback (for example, whether a manual or automatic rollback was initiated).</p>
    pub fn set_rollback_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.rollback_reason = input;
        self
    }
    /// <p>The reason for this instance refresh rollback (for example, whether a manual or automatic rollback was initiated).</p>
    pub fn get_rollback_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.rollback_reason
    }
    /// <p>The date and time at which the rollback began.</p>
    pub fn rollback_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.rollback_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time at which the rollback began.</p>
    pub fn set_rollback_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.rollback_start_time = input;
        self
    }
    /// <p>The date and time at which the rollback began.</p>
    pub fn get_rollback_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.rollback_start_time
    }
    /// <p>Indicates the value of <code>PercentageComplete</code> at the time the rollback started.</p>
    pub fn percentage_complete_on_rollback(mut self, input: i32) -> Self {
        self.percentage_complete_on_rollback = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the value of <code>PercentageComplete</code> at the time the rollback started.</p>
    pub fn set_percentage_complete_on_rollback(mut self, input: ::std::option::Option<i32>) -> Self {
        self.percentage_complete_on_rollback = input;
        self
    }
    /// <p>Indicates the value of <code>PercentageComplete</code> at the time the rollback started.</p>
    pub fn get_percentage_complete_on_rollback(&self) -> &::std::option::Option<i32> {
        &self.percentage_complete_on_rollback
    }
    /// <p>Indicates the value of <code>InstancesToUpdate</code> at the time the rollback started.</p>
    pub fn instances_to_update_on_rollback(mut self, input: i32) -> Self {
        self.instances_to_update_on_rollback = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the value of <code>InstancesToUpdate</code> at the time the rollback started.</p>
    pub fn set_instances_to_update_on_rollback(mut self, input: ::std::option::Option<i32>) -> Self {
        self.instances_to_update_on_rollback = input;
        self
    }
    /// <p>Indicates the value of <code>InstancesToUpdate</code> at the time the rollback started.</p>
    pub fn get_instances_to_update_on_rollback(&self) -> &::std::option::Option<i32> {
        &self.instances_to_update_on_rollback
    }
    /// <p>Reports progress on replacing instances in an Auto Scaling group that has a warm pool. This includes separate details for instances in the warm pool and instances in the Auto Scaling group (the live pool).</p>
    pub fn progress_details_on_rollback(mut self, input: crate::types::InstanceRefreshProgressDetails) -> Self {
        self.progress_details_on_rollback = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reports progress on replacing instances in an Auto Scaling group that has a warm pool. This includes separate details for instances in the warm pool and instances in the Auto Scaling group (the live pool).</p>
    pub fn set_progress_details_on_rollback(mut self, input: ::std::option::Option<crate::types::InstanceRefreshProgressDetails>) -> Self {
        self.progress_details_on_rollback = input;
        self
    }
    /// <p>Reports progress on replacing instances in an Auto Scaling group that has a warm pool. This includes separate details for instances in the warm pool and instances in the Auto Scaling group (the live pool).</p>
    pub fn get_progress_details_on_rollback(&self) -> &::std::option::Option<crate::types::InstanceRefreshProgressDetails> {
        &self.progress_details_on_rollback
    }
    /// Consumes the builder and constructs a [`RollbackDetails`](crate::types::RollbackDetails).
    pub fn build(self) -> crate::types::RollbackDetails {
        crate::types::RollbackDetails {
            rollback_reason: self.rollback_reason,
            rollback_start_time: self.rollback_start_time,
            percentage_complete_on_rollback: self.percentage_complete_on_rollback,
            instances_to_update_on_rollback: self.instances_to_update_on_rollback,
            progress_details_on_rollback: self.progress_details_on_rollback,
        }
    }
}
