// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartReplicationTaskInput {
    /// <p>The Amazon Resource Name (ARN) of the replication task to be started.</p>
    pub replication_task_arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of replication task to start.</p>
    /// <p><code>start-replication</code> is the only valid action that can be used for the first time a task with the migration type of <code>full-load</code>full-load, <code>full-load-and-cdc</code> or <code>cdc</code> is run. Any other action used for the first time on a given task, such as <code>resume-processing</code> and reload-target will result in data errors.</p>
    /// <p>You can also use <code>ReloadTables</code> to reload specific tables that failed during migration instead of restarting the task.</p>
    /// <p>For a <code>full-load</code> task, the resume-processing option will reload any tables that were partially loaded or not yet loaded during the full load phase.</p>
    /// <p>For a <code>full-load-and-cdc</code> task, DMS migrates table data, and then applies data changes that occur on the source. To load all the tables again, and start capturing source changes, use <code>reload-target</code>. Otherwise use <code>resume-processing</code>, to replicate the changes from the last stop position.</p>
    /// <p>For a <code>cdc</code> only task, to start from a specific position, you must use start-replication and also specify the start position. Check the source endpoint DMS documentation for any limitations. For example, not all sources support starting from a time.</p><note>
    /// <p><code>resume-processing</code> is only available for previously executed tasks.</p>
    /// </note>
    pub start_replication_task_type: ::std::option::Option<crate::types::StartReplicationTaskTypeValue>,
    /// <p>Indicates the start time for a change data capture (CDC) operation. Use either CdcStartTime or CdcStartPosition to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>Timestamp Example: --cdc-start-time “2018-03-08T12:12:12”</p>
    pub cdc_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Indicates when you want a change data capture (CDC) operation to start. Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>The value can be in date, checkpoint, or LSN/SCN format.</p>
    /// <p>Date Example: --cdc-start-position “2018-03-08T12:12:12”</p>
    /// <p>Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93"</p>
    /// <p>LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373”</p><note>
    /// <p>When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the <code>slotName</code> extra connection attribute to the name of this logical replication slot. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib">Extra Connection Attributes When Using PostgreSQL as a Source for DMS</a>.</p>
    /// </note>
    pub cdc_start_position: ::std::option::Option<::std::string::String>,
    /// <p>Indicates when you want a change data capture (CDC) operation to stop. The value can be either server time or commit time.</p>
    /// <p>Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12”</p>
    /// <p>Commit time example: --cdc-stop-position “commit_time:2018-02-09T12:12:12“</p>
    pub cdc_stop_position: ::std::option::Option<::std::string::String>,
}
impl StartReplicationTaskInput {
    /// <p>The Amazon Resource Name (ARN) of the replication task to be started.</p>
    pub fn replication_task_arn(&self) -> ::std::option::Option<&str> {
        self.replication_task_arn.as_deref()
    }
    /// <p>The type of replication task to start.</p>
    /// <p><code>start-replication</code> is the only valid action that can be used for the first time a task with the migration type of <code>full-load</code>full-load, <code>full-load-and-cdc</code> or <code>cdc</code> is run. Any other action used for the first time on a given task, such as <code>resume-processing</code> and reload-target will result in data errors.</p>
    /// <p>You can also use <code>ReloadTables</code> to reload specific tables that failed during migration instead of restarting the task.</p>
    /// <p>For a <code>full-load</code> task, the resume-processing option will reload any tables that were partially loaded or not yet loaded during the full load phase.</p>
    /// <p>For a <code>full-load-and-cdc</code> task, DMS migrates table data, and then applies data changes that occur on the source. To load all the tables again, and start capturing source changes, use <code>reload-target</code>. Otherwise use <code>resume-processing</code>, to replicate the changes from the last stop position.</p>
    /// <p>For a <code>cdc</code> only task, to start from a specific position, you must use start-replication and also specify the start position. Check the source endpoint DMS documentation for any limitations. For example, not all sources support starting from a time.</p><note>
    /// <p><code>resume-processing</code> is only available for previously executed tasks.</p>
    /// </note>
    pub fn start_replication_task_type(&self) -> ::std::option::Option<&crate::types::StartReplicationTaskTypeValue> {
        self.start_replication_task_type.as_ref()
    }
    /// <p>Indicates the start time for a change data capture (CDC) operation. Use either CdcStartTime or CdcStartPosition to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>Timestamp Example: --cdc-start-time “2018-03-08T12:12:12”</p>
    pub fn cdc_start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.cdc_start_time.as_ref()
    }
    /// <p>Indicates when you want a change data capture (CDC) operation to start. Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>The value can be in date, checkpoint, or LSN/SCN format.</p>
    /// <p>Date Example: --cdc-start-position “2018-03-08T12:12:12”</p>
    /// <p>Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93"</p>
    /// <p>LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373”</p><note>
    /// <p>When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the <code>slotName</code> extra connection attribute to the name of this logical replication slot. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib">Extra Connection Attributes When Using PostgreSQL as a Source for DMS</a>.</p>
    /// </note>
    pub fn cdc_start_position(&self) -> ::std::option::Option<&str> {
        self.cdc_start_position.as_deref()
    }
    /// <p>Indicates when you want a change data capture (CDC) operation to stop. The value can be either server time or commit time.</p>
    /// <p>Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12”</p>
    /// <p>Commit time example: --cdc-stop-position “commit_time:2018-02-09T12:12:12“</p>
    pub fn cdc_stop_position(&self) -> ::std::option::Option<&str> {
        self.cdc_stop_position.as_deref()
    }
}
impl StartReplicationTaskInput {
    /// Creates a new builder-style object to manufacture [`StartReplicationTaskInput`](crate::operation::start_replication_task::StartReplicationTaskInput).
    pub fn builder() -> crate::operation::start_replication_task::builders::StartReplicationTaskInputBuilder {
        crate::operation::start_replication_task::builders::StartReplicationTaskInputBuilder::default()
    }
}

/// A builder for [`StartReplicationTaskInput`](crate::operation::start_replication_task::StartReplicationTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartReplicationTaskInputBuilder {
    pub(crate) replication_task_arn: ::std::option::Option<::std::string::String>,
    pub(crate) start_replication_task_type: ::std::option::Option<crate::types::StartReplicationTaskTypeValue>,
    pub(crate) cdc_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) cdc_start_position: ::std::option::Option<::std::string::String>,
    pub(crate) cdc_stop_position: ::std::option::Option<::std::string::String>,
}
impl StartReplicationTaskInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the replication task to be started.</p>
    /// This field is required.
    pub fn replication_task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication task to be started.</p>
    pub fn set_replication_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_task_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication task to be started.</p>
    pub fn get_replication_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_task_arn
    }
    /// <p>The type of replication task to start.</p>
    /// <p><code>start-replication</code> is the only valid action that can be used for the first time a task with the migration type of <code>full-load</code>full-load, <code>full-load-and-cdc</code> or <code>cdc</code> is run. Any other action used for the first time on a given task, such as <code>resume-processing</code> and reload-target will result in data errors.</p>
    /// <p>You can also use <code>ReloadTables</code> to reload specific tables that failed during migration instead of restarting the task.</p>
    /// <p>For a <code>full-load</code> task, the resume-processing option will reload any tables that were partially loaded or not yet loaded during the full load phase.</p>
    /// <p>For a <code>full-load-and-cdc</code> task, DMS migrates table data, and then applies data changes that occur on the source. To load all the tables again, and start capturing source changes, use <code>reload-target</code>. Otherwise use <code>resume-processing</code>, to replicate the changes from the last stop position.</p>
    /// <p>For a <code>cdc</code> only task, to start from a specific position, you must use start-replication and also specify the start position. Check the source endpoint DMS documentation for any limitations. For example, not all sources support starting from a time.</p><note>
    /// <p><code>resume-processing</code> is only available for previously executed tasks.</p>
    /// </note>
    /// This field is required.
    pub fn start_replication_task_type(mut self, input: crate::types::StartReplicationTaskTypeValue) -> Self {
        self.start_replication_task_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of replication task to start.</p>
    /// <p><code>start-replication</code> is the only valid action that can be used for the first time a task with the migration type of <code>full-load</code>full-load, <code>full-load-and-cdc</code> or <code>cdc</code> is run. Any other action used for the first time on a given task, such as <code>resume-processing</code> and reload-target will result in data errors.</p>
    /// <p>You can also use <code>ReloadTables</code> to reload specific tables that failed during migration instead of restarting the task.</p>
    /// <p>For a <code>full-load</code> task, the resume-processing option will reload any tables that were partially loaded or not yet loaded during the full load phase.</p>
    /// <p>For a <code>full-load-and-cdc</code> task, DMS migrates table data, and then applies data changes that occur on the source. To load all the tables again, and start capturing source changes, use <code>reload-target</code>. Otherwise use <code>resume-processing</code>, to replicate the changes from the last stop position.</p>
    /// <p>For a <code>cdc</code> only task, to start from a specific position, you must use start-replication and also specify the start position. Check the source endpoint DMS documentation for any limitations. For example, not all sources support starting from a time.</p><note>
    /// <p><code>resume-processing</code> is only available for previously executed tasks.</p>
    /// </note>
    pub fn set_start_replication_task_type(mut self, input: ::std::option::Option<crate::types::StartReplicationTaskTypeValue>) -> Self {
        self.start_replication_task_type = input;
        self
    }
    /// <p>The type of replication task to start.</p>
    /// <p><code>start-replication</code> is the only valid action that can be used for the first time a task with the migration type of <code>full-load</code>full-load, <code>full-load-and-cdc</code> or <code>cdc</code> is run. Any other action used for the first time on a given task, such as <code>resume-processing</code> and reload-target will result in data errors.</p>
    /// <p>You can also use <code>ReloadTables</code> to reload specific tables that failed during migration instead of restarting the task.</p>
    /// <p>For a <code>full-load</code> task, the resume-processing option will reload any tables that were partially loaded or not yet loaded during the full load phase.</p>
    /// <p>For a <code>full-load-and-cdc</code> task, DMS migrates table data, and then applies data changes that occur on the source. To load all the tables again, and start capturing source changes, use <code>reload-target</code>. Otherwise use <code>resume-processing</code>, to replicate the changes from the last stop position.</p>
    /// <p>For a <code>cdc</code> only task, to start from a specific position, you must use start-replication and also specify the start position. Check the source endpoint DMS documentation for any limitations. For example, not all sources support starting from a time.</p><note>
    /// <p><code>resume-processing</code> is only available for previously executed tasks.</p>
    /// </note>
    pub fn get_start_replication_task_type(&self) -> &::std::option::Option<crate::types::StartReplicationTaskTypeValue> {
        &self.start_replication_task_type
    }
    /// <p>Indicates the start time for a change data capture (CDC) operation. Use either CdcStartTime or CdcStartPosition to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>Timestamp Example: --cdc-start-time “2018-03-08T12:12:12”</p>
    pub fn cdc_start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.cdc_start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the start time for a change data capture (CDC) operation. Use either CdcStartTime or CdcStartPosition to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>Timestamp Example: --cdc-start-time “2018-03-08T12:12:12”</p>
    pub fn set_cdc_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.cdc_start_time = input;
        self
    }
    /// <p>Indicates the start time for a change data capture (CDC) operation. Use either CdcStartTime or CdcStartPosition to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>Timestamp Example: --cdc-start-time “2018-03-08T12:12:12”</p>
    pub fn get_cdc_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.cdc_start_time
    }
    /// <p>Indicates when you want a change data capture (CDC) operation to start. Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>The value can be in date, checkpoint, or LSN/SCN format.</p>
    /// <p>Date Example: --cdc-start-position “2018-03-08T12:12:12”</p>
    /// <p>Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93"</p>
    /// <p>LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373”</p><note>
    /// <p>When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the <code>slotName</code> extra connection attribute to the name of this logical replication slot. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib">Extra Connection Attributes When Using PostgreSQL as a Source for DMS</a>.</p>
    /// </note>
    pub fn cdc_start_position(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cdc_start_position = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates when you want a change data capture (CDC) operation to start. Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>The value can be in date, checkpoint, or LSN/SCN format.</p>
    /// <p>Date Example: --cdc-start-position “2018-03-08T12:12:12”</p>
    /// <p>Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93"</p>
    /// <p>LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373”</p><note>
    /// <p>When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the <code>slotName</code> extra connection attribute to the name of this logical replication slot. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib">Extra Connection Attributes When Using PostgreSQL as a Source for DMS</a>.</p>
    /// </note>
    pub fn set_cdc_start_position(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cdc_start_position = input;
        self
    }
    /// <p>Indicates when you want a change data capture (CDC) operation to start. Use either CdcStartPosition or CdcStartTime to specify when you want a CDC operation to start. Specifying both values results in an error.</p>
    /// <p>The value can be in date, checkpoint, or LSN/SCN format.</p>
    /// <p>Date Example: --cdc-start-position “2018-03-08T12:12:12”</p>
    /// <p>Checkpoint Example: --cdc-start-position "checkpoint:V1#27#mysql-bin-changelog.157832:1975:-1:2002:677883278264080:mysql-bin-changelog.157832:1876#0#0#*#0#93"</p>
    /// <p>LSN Example: --cdc-start-position “mysql-bin-changelog.000024:373”</p><note>
    /// <p>When you use this task setting with a source PostgreSQL database, a logical replication slot should already be created and associated with the source endpoint. You can verify this by setting the <code>slotName</code> extra connection attribute to the name of this logical replication slot. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Source.PostgreSQL.html#CHAP_Source.PostgreSQL.ConnectionAttrib">Extra Connection Attributes When Using PostgreSQL as a Source for DMS</a>.</p>
    /// </note>
    pub fn get_cdc_start_position(&self) -> &::std::option::Option<::std::string::String> {
        &self.cdc_start_position
    }
    /// <p>Indicates when you want a change data capture (CDC) operation to stop. The value can be either server time or commit time.</p>
    /// <p>Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12”</p>
    /// <p>Commit time example: --cdc-stop-position “commit_time:2018-02-09T12:12:12“</p>
    pub fn cdc_stop_position(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cdc_stop_position = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates when you want a change data capture (CDC) operation to stop. The value can be either server time or commit time.</p>
    /// <p>Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12”</p>
    /// <p>Commit time example: --cdc-stop-position “commit_time:2018-02-09T12:12:12“</p>
    pub fn set_cdc_stop_position(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cdc_stop_position = input;
        self
    }
    /// <p>Indicates when you want a change data capture (CDC) operation to stop. The value can be either server time or commit time.</p>
    /// <p>Server time example: --cdc-stop-position “server_time:2018-02-09T12:12:12”</p>
    /// <p>Commit time example: --cdc-stop-position “commit_time:2018-02-09T12:12:12“</p>
    pub fn get_cdc_stop_position(&self) -> &::std::option::Option<::std::string::String> {
        &self.cdc_stop_position
    }
    /// Consumes the builder and constructs a [`StartReplicationTaskInput`](crate::operation::start_replication_task::StartReplicationTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_replication_task::StartReplicationTaskInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::start_replication_task::StartReplicationTaskInput {
            replication_task_arn: self.replication_task_arn,
            start_replication_task_type: self.start_replication_task_type,
            cdc_start_time: self.cdc_start_time,
            cdc_start_position: self.cdc_start_position,
            cdc_stop_position: self.cdc_stop_position,
        })
    }
}
