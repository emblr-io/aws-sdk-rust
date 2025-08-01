// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information about a pending maintenance action for a resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PendingMaintenanceAction {
    /// <p>The type of pending maintenance action that is available for the resource.</p>
    /// <p>For more information about maintenance actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html">Maintaining a DB instance</a>.</p>
    /// <p>Valid Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ca-certificate-rotation</code></p></li>
    /// <li>
    /// <p><code>db-upgrade</code></p></li>
    /// <li>
    /// <p><code>hardware-maintenance</code></p></li>
    /// <li>
    /// <p><code>os-upgrade</code></p></li>
    /// <li>
    /// <p><code>system-update</code></p></li>
    /// </ul>
    /// <p>For more information about these actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-aurora">Maintenance actions for Amazon Aurora</a> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-rds">Maintenance actions for Amazon RDS</a>.</p>
    pub action: ::std::option::Option<::std::string::String>,
    /// <p>The date of the maintenance window when the action is applied. The maintenance action is applied to the resource during its first maintenance window after this date.</p>
    pub auto_applied_after_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date when the maintenance action is automatically applied.</p>
    /// <p>On this date, the maintenance action is applied to the resource as soon as possible, regardless of the maintenance window for the resource. There might be a delay of one or more days from this date before the maintenance action is applied.</p>
    pub forced_apply_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Indicates the type of opt-in request that has been received for the resource.</p>
    pub opt_in_status: ::std::option::Option<::std::string::String>,
    /// <p>The effective date when the pending maintenance action is applied to the resource. This date takes into account opt-in requests received from the <code>ApplyPendingMaintenanceAction</code> API, the <code>AutoAppliedAfterDate</code>, and the <code>ForcedApplyDate</code>. This value is blank if an opt-in request has not been received and nothing has been specified as <code>AutoAppliedAfterDate</code> or <code>ForcedApplyDate</code>.</p>
    pub current_apply_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A description providing more detail about the maintenance action.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl PendingMaintenanceAction {
    /// <p>The type of pending maintenance action that is available for the resource.</p>
    /// <p>For more information about maintenance actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html">Maintaining a DB instance</a>.</p>
    /// <p>Valid Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ca-certificate-rotation</code></p></li>
    /// <li>
    /// <p><code>db-upgrade</code></p></li>
    /// <li>
    /// <p><code>hardware-maintenance</code></p></li>
    /// <li>
    /// <p><code>os-upgrade</code></p></li>
    /// <li>
    /// <p><code>system-update</code></p></li>
    /// </ul>
    /// <p>For more information about these actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-aurora">Maintenance actions for Amazon Aurora</a> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-rds">Maintenance actions for Amazon RDS</a>.</p>
    pub fn action(&self) -> ::std::option::Option<&str> {
        self.action.as_deref()
    }
    /// <p>The date of the maintenance window when the action is applied. The maintenance action is applied to the resource during its first maintenance window after this date.</p>
    pub fn auto_applied_after_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.auto_applied_after_date.as_ref()
    }
    /// <p>The date when the maintenance action is automatically applied.</p>
    /// <p>On this date, the maintenance action is applied to the resource as soon as possible, regardless of the maintenance window for the resource. There might be a delay of one or more days from this date before the maintenance action is applied.</p>
    pub fn forced_apply_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.forced_apply_date.as_ref()
    }
    /// <p>Indicates the type of opt-in request that has been received for the resource.</p>
    pub fn opt_in_status(&self) -> ::std::option::Option<&str> {
        self.opt_in_status.as_deref()
    }
    /// <p>The effective date when the pending maintenance action is applied to the resource. This date takes into account opt-in requests received from the <code>ApplyPendingMaintenanceAction</code> API, the <code>AutoAppliedAfterDate</code>, and the <code>ForcedApplyDate</code>. This value is blank if an opt-in request has not been received and nothing has been specified as <code>AutoAppliedAfterDate</code> or <code>ForcedApplyDate</code>.</p>
    pub fn current_apply_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.current_apply_date.as_ref()
    }
    /// <p>A description providing more detail about the maintenance action.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl PendingMaintenanceAction {
    /// Creates a new builder-style object to manufacture [`PendingMaintenanceAction`](crate::types::PendingMaintenanceAction).
    pub fn builder() -> crate::types::builders::PendingMaintenanceActionBuilder {
        crate::types::builders::PendingMaintenanceActionBuilder::default()
    }
}

/// A builder for [`PendingMaintenanceAction`](crate::types::PendingMaintenanceAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PendingMaintenanceActionBuilder {
    pub(crate) action: ::std::option::Option<::std::string::String>,
    pub(crate) auto_applied_after_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) forced_apply_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) opt_in_status: ::std::option::Option<::std::string::String>,
    pub(crate) current_apply_date: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl PendingMaintenanceActionBuilder {
    /// <p>The type of pending maintenance action that is available for the resource.</p>
    /// <p>For more information about maintenance actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html">Maintaining a DB instance</a>.</p>
    /// <p>Valid Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ca-certificate-rotation</code></p></li>
    /// <li>
    /// <p><code>db-upgrade</code></p></li>
    /// <li>
    /// <p><code>hardware-maintenance</code></p></li>
    /// <li>
    /// <p><code>os-upgrade</code></p></li>
    /// <li>
    /// <p><code>system-update</code></p></li>
    /// </ul>
    /// <p>For more information about these actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-aurora">Maintenance actions for Amazon Aurora</a> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-rds">Maintenance actions for Amazon RDS</a>.</p>
    pub fn action(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of pending maintenance action that is available for the resource.</p>
    /// <p>For more information about maintenance actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html">Maintaining a DB instance</a>.</p>
    /// <p>Valid Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ca-certificate-rotation</code></p></li>
    /// <li>
    /// <p><code>db-upgrade</code></p></li>
    /// <li>
    /// <p><code>hardware-maintenance</code></p></li>
    /// <li>
    /// <p><code>os-upgrade</code></p></li>
    /// <li>
    /// <p><code>system-update</code></p></li>
    /// </ul>
    /// <p>For more information about these actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-aurora">Maintenance actions for Amazon Aurora</a> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-rds">Maintenance actions for Amazon RDS</a>.</p>
    pub fn set_action(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action = input;
        self
    }
    /// <p>The type of pending maintenance action that is available for the resource.</p>
    /// <p>For more information about maintenance actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html">Maintaining a DB instance</a>.</p>
    /// <p>Valid Values:</p>
    /// <ul>
    /// <li>
    /// <p><code>ca-certificate-rotation</code></p></li>
    /// <li>
    /// <p><code>db-upgrade</code></p></li>
    /// <li>
    /// <p><code>hardware-maintenance</code></p></li>
    /// <li>
    /// <p><code>os-upgrade</code></p></li>
    /// <li>
    /// <p><code>system-update</code></p></li>
    /// </ul>
    /// <p>For more information about these actions, see <a href="https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-aurora">Maintenance actions for Amazon Aurora</a> or <a href="https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Maintenance.html#maintenance-actions-rds">Maintenance actions for Amazon RDS</a>.</p>
    pub fn get_action(&self) -> &::std::option::Option<::std::string::String> {
        &self.action
    }
    /// <p>The date of the maintenance window when the action is applied. The maintenance action is applied to the resource during its first maintenance window after this date.</p>
    pub fn auto_applied_after_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.auto_applied_after_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date of the maintenance window when the action is applied. The maintenance action is applied to the resource during its first maintenance window after this date.</p>
    pub fn set_auto_applied_after_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.auto_applied_after_date = input;
        self
    }
    /// <p>The date of the maintenance window when the action is applied. The maintenance action is applied to the resource during its first maintenance window after this date.</p>
    pub fn get_auto_applied_after_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.auto_applied_after_date
    }
    /// <p>The date when the maintenance action is automatically applied.</p>
    /// <p>On this date, the maintenance action is applied to the resource as soon as possible, regardless of the maintenance window for the resource. There might be a delay of one or more days from this date before the maintenance action is applied.</p>
    pub fn forced_apply_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.forced_apply_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date when the maintenance action is automatically applied.</p>
    /// <p>On this date, the maintenance action is applied to the resource as soon as possible, regardless of the maintenance window for the resource. There might be a delay of one or more days from this date before the maintenance action is applied.</p>
    pub fn set_forced_apply_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.forced_apply_date = input;
        self
    }
    /// <p>The date when the maintenance action is automatically applied.</p>
    /// <p>On this date, the maintenance action is applied to the resource as soon as possible, regardless of the maintenance window for the resource. There might be a delay of one or more days from this date before the maintenance action is applied.</p>
    pub fn get_forced_apply_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.forced_apply_date
    }
    /// <p>Indicates the type of opt-in request that has been received for the resource.</p>
    pub fn opt_in_status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.opt_in_status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates the type of opt-in request that has been received for the resource.</p>
    pub fn set_opt_in_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.opt_in_status = input;
        self
    }
    /// <p>Indicates the type of opt-in request that has been received for the resource.</p>
    pub fn get_opt_in_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.opt_in_status
    }
    /// <p>The effective date when the pending maintenance action is applied to the resource. This date takes into account opt-in requests received from the <code>ApplyPendingMaintenanceAction</code> API, the <code>AutoAppliedAfterDate</code>, and the <code>ForcedApplyDate</code>. This value is blank if an opt-in request has not been received and nothing has been specified as <code>AutoAppliedAfterDate</code> or <code>ForcedApplyDate</code>.</p>
    pub fn current_apply_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.current_apply_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The effective date when the pending maintenance action is applied to the resource. This date takes into account opt-in requests received from the <code>ApplyPendingMaintenanceAction</code> API, the <code>AutoAppliedAfterDate</code>, and the <code>ForcedApplyDate</code>. This value is blank if an opt-in request has not been received and nothing has been specified as <code>AutoAppliedAfterDate</code> or <code>ForcedApplyDate</code>.</p>
    pub fn set_current_apply_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.current_apply_date = input;
        self
    }
    /// <p>The effective date when the pending maintenance action is applied to the resource. This date takes into account opt-in requests received from the <code>ApplyPendingMaintenanceAction</code> API, the <code>AutoAppliedAfterDate</code>, and the <code>ForcedApplyDate</code>. This value is blank if an opt-in request has not been received and nothing has been specified as <code>AutoAppliedAfterDate</code> or <code>ForcedApplyDate</code>.</p>
    pub fn get_current_apply_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.current_apply_date
    }
    /// <p>A description providing more detail about the maintenance action.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description providing more detail about the maintenance action.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description providing more detail about the maintenance action.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`PendingMaintenanceAction`](crate::types::PendingMaintenanceAction).
    pub fn build(self) -> crate::types::PendingMaintenanceAction {
        crate::types::PendingMaintenanceAction {
            action: self.action,
            auto_applied_after_date: self.auto_applied_after_date,
            forced_apply_date: self.forced_apply_date,
            opt_in_status: self.opt_in_status,
            current_apply_date: self.current_apply_date,
            description: self.description,
        }
    }
}
