// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyReplicationTaskInput {
    /// <p>The Amazon Resource Name (ARN) of the replication task.</p>
    pub replication_task_arn: ::std::option::Option<::std::string::String>,
    /// <p>The replication task identifier.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain 1-255 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub replication_task_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The migration type. Valid values: <code>full-load</code> | <code>cdc</code> | <code>full-load-and-cdc</code></p>
    pub migration_type: ::std::option::Option<crate::types::MigrationTypeValue>,
    /// <p>When using the CLI or boto3, provide the path of the JSON file that contains the table mappings. Precede the path with <code>file://</code>. For example, <code>--table-mappings file://mappingfile.json</code>. When working with the DMS API, provide the JSON as the parameter value.</p>
    pub table_mappings: ::std::option::Option<::std::string::String>,
    /// <p>JSON file that contains settings for the task, such as task metadata settings.</p>
    pub replication_task_settings: ::std::option::Option<::std::string::String>,
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
    /// <p>Supplemental information that the task requires to migrate the data for certain source and target endpoints. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.TaskData.html">Specifying Supplemental Data for Task Settings</a> in the <i>Database Migration Service User Guide.</i></p>
    pub task_data: ::std::option::Option<::std::string::String>,
}
impl ModifyReplicationTaskInput {
    /// <p>The Amazon Resource Name (ARN) of the replication task.</p>
    pub fn replication_task_arn(&self) -> ::std::option::Option<&str> {
        self.replication_task_arn.as_deref()
    }
    /// <p>The replication task identifier.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain 1-255 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub fn replication_task_identifier(&self) -> ::std::option::Option<&str> {
        self.replication_task_identifier.as_deref()
    }
    /// <p>The migration type. Valid values: <code>full-load</code> | <code>cdc</code> | <code>full-load-and-cdc</code></p>
    pub fn migration_type(&self) -> ::std::option::Option<&crate::types::MigrationTypeValue> {
        self.migration_type.as_ref()
    }
    /// <p>When using the CLI or boto3, provide the path of the JSON file that contains the table mappings. Precede the path with <code>file://</code>. For example, <code>--table-mappings file://mappingfile.json</code>. When working with the DMS API, provide the JSON as the parameter value.</p>
    pub fn table_mappings(&self) -> ::std::option::Option<&str> {
        self.table_mappings.as_deref()
    }
    /// <p>JSON file that contains settings for the task, such as task metadata settings.</p>
    pub fn replication_task_settings(&self) -> ::std::option::Option<&str> {
        self.replication_task_settings.as_deref()
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
    /// <p>Supplemental information that the task requires to migrate the data for certain source and target endpoints. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.TaskData.html">Specifying Supplemental Data for Task Settings</a> in the <i>Database Migration Service User Guide.</i></p>
    pub fn task_data(&self) -> ::std::option::Option<&str> {
        self.task_data.as_deref()
    }
}
impl ModifyReplicationTaskInput {
    /// Creates a new builder-style object to manufacture [`ModifyReplicationTaskInput`](crate::operation::modify_replication_task::ModifyReplicationTaskInput).
    pub fn builder() -> crate::operation::modify_replication_task::builders::ModifyReplicationTaskInputBuilder {
        crate::operation::modify_replication_task::builders::ModifyReplicationTaskInputBuilder::default()
    }
}

/// A builder for [`ModifyReplicationTaskInput`](crate::operation::modify_replication_task::ModifyReplicationTaskInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyReplicationTaskInputBuilder {
    pub(crate) replication_task_arn: ::std::option::Option<::std::string::String>,
    pub(crate) replication_task_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) migration_type: ::std::option::Option<crate::types::MigrationTypeValue>,
    pub(crate) table_mappings: ::std::option::Option<::std::string::String>,
    pub(crate) replication_task_settings: ::std::option::Option<::std::string::String>,
    pub(crate) cdc_start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) cdc_start_position: ::std::option::Option<::std::string::String>,
    pub(crate) cdc_stop_position: ::std::option::Option<::std::string::String>,
    pub(crate) task_data: ::std::option::Option<::std::string::String>,
}
impl ModifyReplicationTaskInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the replication task.</p>
    /// This field is required.
    pub fn replication_task_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_task_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication task.</p>
    pub fn set_replication_task_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_task_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the replication task.</p>
    pub fn get_replication_task_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_task_arn
    }
    /// <p>The replication task identifier.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain 1-255 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub fn replication_task_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_task_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The replication task identifier.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain 1-255 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub fn set_replication_task_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_task_identifier = input;
        self
    }
    /// <p>The replication task identifier.</p>
    /// <p>Constraints:</p>
    /// <ul>
    /// <li>
    /// <p>Must contain 1-255 alphanumeric characters or hyphens.</p></li>
    /// <li>
    /// <p>First character must be a letter.</p></li>
    /// <li>
    /// <p>Cannot end with a hyphen or contain two consecutive hyphens.</p></li>
    /// </ul>
    pub fn get_replication_task_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_task_identifier
    }
    /// <p>The migration type. Valid values: <code>full-load</code> | <code>cdc</code> | <code>full-load-and-cdc</code></p>
    pub fn migration_type(mut self, input: crate::types::MigrationTypeValue) -> Self {
        self.migration_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The migration type. Valid values: <code>full-load</code> | <code>cdc</code> | <code>full-load-and-cdc</code></p>
    pub fn set_migration_type(mut self, input: ::std::option::Option<crate::types::MigrationTypeValue>) -> Self {
        self.migration_type = input;
        self
    }
    /// <p>The migration type. Valid values: <code>full-load</code> | <code>cdc</code> | <code>full-load-and-cdc</code></p>
    pub fn get_migration_type(&self) -> &::std::option::Option<crate::types::MigrationTypeValue> {
        &self.migration_type
    }
    /// <p>When using the CLI or boto3, provide the path of the JSON file that contains the table mappings. Precede the path with <code>file://</code>. For example, <code>--table-mappings file://mappingfile.json</code>. When working with the DMS API, provide the JSON as the parameter value.</p>
    pub fn table_mappings(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_mappings = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>When using the CLI or boto3, provide the path of the JSON file that contains the table mappings. Precede the path with <code>file://</code>. For example, <code>--table-mappings file://mappingfile.json</code>. When working with the DMS API, provide the JSON as the parameter value.</p>
    pub fn set_table_mappings(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_mappings = input;
        self
    }
    /// <p>When using the CLI or boto3, provide the path of the JSON file that contains the table mappings. Precede the path with <code>file://</code>. For example, <code>--table-mappings file://mappingfile.json</code>. When working with the DMS API, provide the JSON as the parameter value.</p>
    pub fn get_table_mappings(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_mappings
    }
    /// <p>JSON file that contains settings for the task, such as task metadata settings.</p>
    pub fn replication_task_settings(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replication_task_settings = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>JSON file that contains settings for the task, such as task metadata settings.</p>
    pub fn set_replication_task_settings(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replication_task_settings = input;
        self
    }
    /// <p>JSON file that contains settings for the task, such as task metadata settings.</p>
    pub fn get_replication_task_settings(&self) -> &::std::option::Option<::std::string::String> {
        &self.replication_task_settings
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
    /// <p>Supplemental information that the task requires to migrate the data for certain source and target endpoints. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.TaskData.html">Specifying Supplemental Data for Task Settings</a> in the <i>Database Migration Service User Guide.</i></p>
    pub fn task_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.task_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Supplemental information that the task requires to migrate the data for certain source and target endpoints. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.TaskData.html">Specifying Supplemental Data for Task Settings</a> in the <i>Database Migration Service User Guide.</i></p>
    pub fn set_task_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.task_data = input;
        self
    }
    /// <p>Supplemental information that the task requires to migrate the data for certain source and target endpoints. For more information, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Tasks.TaskData.html">Specifying Supplemental Data for Task Settings</a> in the <i>Database Migration Service User Guide.</i></p>
    pub fn get_task_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.task_data
    }
    /// Consumes the builder and constructs a [`ModifyReplicationTaskInput`](crate::operation::modify_replication_task::ModifyReplicationTaskInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::modify_replication_task::ModifyReplicationTaskInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::modify_replication_task::ModifyReplicationTaskInput {
            replication_task_arn: self.replication_task_arn,
            replication_task_identifier: self.replication_task_identifier,
            migration_type: self.migration_type,
            table_mappings: self.table_mappings,
            replication_task_settings: self.replication_task_settings,
            cdc_start_time: self.cdc_start_time,
            cdc_start_position: self.cdc_start_position,
            cdc_stop_position: self.cdc_stop_position,
            task_data: self.task_data,
        })
    }
}
