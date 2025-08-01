// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the SnapLock configuration for an FSx for ONTAP SnapLock volume.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SnaplockConfiguration {
    /// <p>Enables or disables the audit log volume for an FSx for ONTAP SnapLock volume. The default value is <code>false</code>. If you set <code>AuditLogVolume</code> to <code>true</code>, the SnapLock volume is created as an audit log volume. The minimum retention period for an audit log volume is six months.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/how-snaplock-works.html#snaplock-audit-log-volume"> SnapLock audit log volumes</a>.</p>
    pub audit_log_volume: ::std::option::Option<bool>,
    /// <p>The configuration object for setting the autocommit period of files in an FSx for ONTAP SnapLock volume.</p>
    pub autocommit_period: ::std::option::Option<crate::types::AutocommitPeriod>,
    /// <p>Enables, disables, or permanently disables privileged delete on an FSx for ONTAP SnapLock Enterprise volume. Enabling privileged delete allows SnapLock administrators to delete write once, read many (WORM) files even if they have active retention periods. <code>PERMANENTLY_DISABLED</code> is a terminal state. If privileged delete is permanently disabled on a SnapLock volume, you can't re-enable it. The default value is <code>DISABLED</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html#privileged-delete">Privileged delete</a>.</p>
    pub privileged_delete: ::std::option::Option<crate::types::PrivilegedDelete>,
    /// <p>Specifies the retention period of an FSx for ONTAP SnapLock volume.</p>
    pub retention_period: ::std::option::Option<crate::types::SnaplockRetentionPeriod>,
    /// <p>Specifies the retention mode of an FSx for ONTAP SnapLock volume. After it is set, it can't be changed. You can choose one of the following retention modes:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLIANCE</code>: Files transitioned to write once, read many (WORM) on a Compliance volume can't be deleted until their retention periods expire. This retention mode is used to address government or industry-specific mandates or to protect against ransomware attacks. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-compliance.html">SnapLock Compliance</a>.</p></li>
    /// <li>
    /// <p><code>ENTERPRISE</code>: Files transitioned to WORM on an Enterprise volume can be deleted by authorized users before their retention periods expire using privileged delete. This retention mode is used to advance an organization's data integrity and internal compliance or to test retention settings before using SnapLock Compliance. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html">SnapLock Enterprise</a>.</p></li>
    /// </ul>
    pub snaplock_type: ::std::option::Option<crate::types::SnaplockType>,
    /// <p>Enables or disables volume-append mode on an FSx for ONTAP SnapLock volume. Volume-append mode allows you to create WORM-appendable files and write data to them incrementally. The default value is <code>false</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/worm-state.html#worm-state-append">Volume-append mode</a>.</p>
    pub volume_append_mode_enabled: ::std::option::Option<bool>,
}
impl SnaplockConfiguration {
    /// <p>Enables or disables the audit log volume for an FSx for ONTAP SnapLock volume. The default value is <code>false</code>. If you set <code>AuditLogVolume</code> to <code>true</code>, the SnapLock volume is created as an audit log volume. The minimum retention period for an audit log volume is six months.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/how-snaplock-works.html#snaplock-audit-log-volume"> SnapLock audit log volumes</a>.</p>
    pub fn audit_log_volume(&self) -> ::std::option::Option<bool> {
        self.audit_log_volume
    }
    /// <p>The configuration object for setting the autocommit period of files in an FSx for ONTAP SnapLock volume.</p>
    pub fn autocommit_period(&self) -> ::std::option::Option<&crate::types::AutocommitPeriod> {
        self.autocommit_period.as_ref()
    }
    /// <p>Enables, disables, or permanently disables privileged delete on an FSx for ONTAP SnapLock Enterprise volume. Enabling privileged delete allows SnapLock administrators to delete write once, read many (WORM) files even if they have active retention periods. <code>PERMANENTLY_DISABLED</code> is a terminal state. If privileged delete is permanently disabled on a SnapLock volume, you can't re-enable it. The default value is <code>DISABLED</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html#privileged-delete">Privileged delete</a>.</p>
    pub fn privileged_delete(&self) -> ::std::option::Option<&crate::types::PrivilegedDelete> {
        self.privileged_delete.as_ref()
    }
    /// <p>Specifies the retention period of an FSx for ONTAP SnapLock volume.</p>
    pub fn retention_period(&self) -> ::std::option::Option<&crate::types::SnaplockRetentionPeriod> {
        self.retention_period.as_ref()
    }
    /// <p>Specifies the retention mode of an FSx for ONTAP SnapLock volume. After it is set, it can't be changed. You can choose one of the following retention modes:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLIANCE</code>: Files transitioned to write once, read many (WORM) on a Compliance volume can't be deleted until their retention periods expire. This retention mode is used to address government or industry-specific mandates or to protect against ransomware attacks. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-compliance.html">SnapLock Compliance</a>.</p></li>
    /// <li>
    /// <p><code>ENTERPRISE</code>: Files transitioned to WORM on an Enterprise volume can be deleted by authorized users before their retention periods expire using privileged delete. This retention mode is used to advance an organization's data integrity and internal compliance or to test retention settings before using SnapLock Compliance. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html">SnapLock Enterprise</a>.</p></li>
    /// </ul>
    pub fn snaplock_type(&self) -> ::std::option::Option<&crate::types::SnaplockType> {
        self.snaplock_type.as_ref()
    }
    /// <p>Enables or disables volume-append mode on an FSx for ONTAP SnapLock volume. Volume-append mode allows you to create WORM-appendable files and write data to them incrementally. The default value is <code>false</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/worm-state.html#worm-state-append">Volume-append mode</a>.</p>
    pub fn volume_append_mode_enabled(&self) -> ::std::option::Option<bool> {
        self.volume_append_mode_enabled
    }
}
impl SnaplockConfiguration {
    /// Creates a new builder-style object to manufacture [`SnaplockConfiguration`](crate::types::SnaplockConfiguration).
    pub fn builder() -> crate::types::builders::SnaplockConfigurationBuilder {
        crate::types::builders::SnaplockConfigurationBuilder::default()
    }
}

/// A builder for [`SnaplockConfiguration`](crate::types::SnaplockConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SnaplockConfigurationBuilder {
    pub(crate) audit_log_volume: ::std::option::Option<bool>,
    pub(crate) autocommit_period: ::std::option::Option<crate::types::AutocommitPeriod>,
    pub(crate) privileged_delete: ::std::option::Option<crate::types::PrivilegedDelete>,
    pub(crate) retention_period: ::std::option::Option<crate::types::SnaplockRetentionPeriod>,
    pub(crate) snaplock_type: ::std::option::Option<crate::types::SnaplockType>,
    pub(crate) volume_append_mode_enabled: ::std::option::Option<bool>,
}
impl SnaplockConfigurationBuilder {
    /// <p>Enables or disables the audit log volume for an FSx for ONTAP SnapLock volume. The default value is <code>false</code>. If you set <code>AuditLogVolume</code> to <code>true</code>, the SnapLock volume is created as an audit log volume. The minimum retention period for an audit log volume is six months.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/how-snaplock-works.html#snaplock-audit-log-volume"> SnapLock audit log volumes</a>.</p>
    pub fn audit_log_volume(mut self, input: bool) -> Self {
        self.audit_log_volume = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables the audit log volume for an FSx for ONTAP SnapLock volume. The default value is <code>false</code>. If you set <code>AuditLogVolume</code> to <code>true</code>, the SnapLock volume is created as an audit log volume. The minimum retention period for an audit log volume is six months.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/how-snaplock-works.html#snaplock-audit-log-volume"> SnapLock audit log volumes</a>.</p>
    pub fn set_audit_log_volume(mut self, input: ::std::option::Option<bool>) -> Self {
        self.audit_log_volume = input;
        self
    }
    /// <p>Enables or disables the audit log volume for an FSx for ONTAP SnapLock volume. The default value is <code>false</code>. If you set <code>AuditLogVolume</code> to <code>true</code>, the SnapLock volume is created as an audit log volume. The minimum retention period for an audit log volume is six months.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/how-snaplock-works.html#snaplock-audit-log-volume"> SnapLock audit log volumes</a>.</p>
    pub fn get_audit_log_volume(&self) -> &::std::option::Option<bool> {
        &self.audit_log_volume
    }
    /// <p>The configuration object for setting the autocommit period of files in an FSx for ONTAP SnapLock volume.</p>
    pub fn autocommit_period(mut self, input: crate::types::AutocommitPeriod) -> Self {
        self.autocommit_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration object for setting the autocommit period of files in an FSx for ONTAP SnapLock volume.</p>
    pub fn set_autocommit_period(mut self, input: ::std::option::Option<crate::types::AutocommitPeriod>) -> Self {
        self.autocommit_period = input;
        self
    }
    /// <p>The configuration object for setting the autocommit period of files in an FSx for ONTAP SnapLock volume.</p>
    pub fn get_autocommit_period(&self) -> &::std::option::Option<crate::types::AutocommitPeriod> {
        &self.autocommit_period
    }
    /// <p>Enables, disables, or permanently disables privileged delete on an FSx for ONTAP SnapLock Enterprise volume. Enabling privileged delete allows SnapLock administrators to delete write once, read many (WORM) files even if they have active retention periods. <code>PERMANENTLY_DISABLED</code> is a terminal state. If privileged delete is permanently disabled on a SnapLock volume, you can't re-enable it. The default value is <code>DISABLED</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html#privileged-delete">Privileged delete</a>.</p>
    pub fn privileged_delete(mut self, input: crate::types::PrivilegedDelete) -> Self {
        self.privileged_delete = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables, disables, or permanently disables privileged delete on an FSx for ONTAP SnapLock Enterprise volume. Enabling privileged delete allows SnapLock administrators to delete write once, read many (WORM) files even if they have active retention periods. <code>PERMANENTLY_DISABLED</code> is a terminal state. If privileged delete is permanently disabled on a SnapLock volume, you can't re-enable it. The default value is <code>DISABLED</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html#privileged-delete">Privileged delete</a>.</p>
    pub fn set_privileged_delete(mut self, input: ::std::option::Option<crate::types::PrivilegedDelete>) -> Self {
        self.privileged_delete = input;
        self
    }
    /// <p>Enables, disables, or permanently disables privileged delete on an FSx for ONTAP SnapLock Enterprise volume. Enabling privileged delete allows SnapLock administrators to delete write once, read many (WORM) files even if they have active retention periods. <code>PERMANENTLY_DISABLED</code> is a terminal state. If privileged delete is permanently disabled on a SnapLock volume, you can't re-enable it. The default value is <code>DISABLED</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html#privileged-delete">Privileged delete</a>.</p>
    pub fn get_privileged_delete(&self) -> &::std::option::Option<crate::types::PrivilegedDelete> {
        &self.privileged_delete
    }
    /// <p>Specifies the retention period of an FSx for ONTAP SnapLock volume.</p>
    pub fn retention_period(mut self, input: crate::types::SnaplockRetentionPeriod) -> Self {
        self.retention_period = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the retention period of an FSx for ONTAP SnapLock volume.</p>
    pub fn set_retention_period(mut self, input: ::std::option::Option<crate::types::SnaplockRetentionPeriod>) -> Self {
        self.retention_period = input;
        self
    }
    /// <p>Specifies the retention period of an FSx for ONTAP SnapLock volume.</p>
    pub fn get_retention_period(&self) -> &::std::option::Option<crate::types::SnaplockRetentionPeriod> {
        &self.retention_period
    }
    /// <p>Specifies the retention mode of an FSx for ONTAP SnapLock volume. After it is set, it can't be changed. You can choose one of the following retention modes:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLIANCE</code>: Files transitioned to write once, read many (WORM) on a Compliance volume can't be deleted until their retention periods expire. This retention mode is used to address government or industry-specific mandates or to protect against ransomware attacks. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-compliance.html">SnapLock Compliance</a>.</p></li>
    /// <li>
    /// <p><code>ENTERPRISE</code>: Files transitioned to WORM on an Enterprise volume can be deleted by authorized users before their retention periods expire using privileged delete. This retention mode is used to advance an organization's data integrity and internal compliance or to test retention settings before using SnapLock Compliance. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html">SnapLock Enterprise</a>.</p></li>
    /// </ul>
    pub fn snaplock_type(mut self, input: crate::types::SnaplockType) -> Self {
        self.snaplock_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the retention mode of an FSx for ONTAP SnapLock volume. After it is set, it can't be changed. You can choose one of the following retention modes:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLIANCE</code>: Files transitioned to write once, read many (WORM) on a Compliance volume can't be deleted until their retention periods expire. This retention mode is used to address government or industry-specific mandates or to protect against ransomware attacks. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-compliance.html">SnapLock Compliance</a>.</p></li>
    /// <li>
    /// <p><code>ENTERPRISE</code>: Files transitioned to WORM on an Enterprise volume can be deleted by authorized users before their retention periods expire using privileged delete. This retention mode is used to advance an organization's data integrity and internal compliance or to test retention settings before using SnapLock Compliance. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html">SnapLock Enterprise</a>.</p></li>
    /// </ul>
    pub fn set_snaplock_type(mut self, input: ::std::option::Option<crate::types::SnaplockType>) -> Self {
        self.snaplock_type = input;
        self
    }
    /// <p>Specifies the retention mode of an FSx for ONTAP SnapLock volume. After it is set, it can't be changed. You can choose one of the following retention modes:</p>
    /// <ul>
    /// <li>
    /// <p><code>COMPLIANCE</code>: Files transitioned to write once, read many (WORM) on a Compliance volume can't be deleted until their retention periods expire. This retention mode is used to address government or industry-specific mandates or to protect against ransomware attacks. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-compliance.html">SnapLock Compliance</a>.</p></li>
    /// <li>
    /// <p><code>ENTERPRISE</code>: Files transitioned to WORM on an Enterprise volume can be deleted by authorized users before their retention periods expire using privileged delete. This retention mode is used to advance an organization's data integrity and internal compliance or to test retention settings before using SnapLock Compliance. For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/snaplock-enterprise.html">SnapLock Enterprise</a>.</p></li>
    /// </ul>
    pub fn get_snaplock_type(&self) -> &::std::option::Option<crate::types::SnaplockType> {
        &self.snaplock_type
    }
    /// <p>Enables or disables volume-append mode on an FSx for ONTAP SnapLock volume. Volume-append mode allows you to create WORM-appendable files and write data to them incrementally. The default value is <code>false</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/worm-state.html#worm-state-append">Volume-append mode</a>.</p>
    pub fn volume_append_mode_enabled(mut self, input: bool) -> Self {
        self.volume_append_mode_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables or disables volume-append mode on an FSx for ONTAP SnapLock volume. Volume-append mode allows you to create WORM-appendable files and write data to them incrementally. The default value is <code>false</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/worm-state.html#worm-state-append">Volume-append mode</a>.</p>
    pub fn set_volume_append_mode_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.volume_append_mode_enabled = input;
        self
    }
    /// <p>Enables or disables volume-append mode on an FSx for ONTAP SnapLock volume. Volume-append mode allows you to create WORM-appendable files and write data to them incrementally. The default value is <code>false</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/worm-state.html#worm-state-append">Volume-append mode</a>.</p>
    pub fn get_volume_append_mode_enabled(&self) -> &::std::option::Option<bool> {
        &self.volume_append_mode_enabled
    }
    /// Consumes the builder and constructs a [`SnaplockConfiguration`](crate::types::SnaplockConfiguration).
    pub fn build(self) -> crate::types::SnaplockConfiguration {
        crate::types::SnaplockConfiguration {
            audit_log_volume: self.audit_log_volume,
            autocommit_period: self.autocommit_period,
            privileged_delete: self.privileged_delete,
            retention_period: self.retention_period,
            snaplock_type: self.snaplock_type,
            volume_append_mode_enabled: self.volume_append_mode_enabled,
        }
    }
}
