// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides information that defines an IBM Db2 LUW endpoint.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct IbmDb2Settings {
    /// <p>Database name for the endpoint.</p>
    pub database_name: ::std::option::Option<::std::string::String>,
    /// <p>Endpoint connection password.</p>
    pub password: ::std::option::Option<::std::string::String>,
    /// <p>Endpoint TCP port. The default value is 50000.</p>
    pub port: ::std::option::Option<i32>,
    /// <p>Fully qualified domain name of the endpoint.</p>
    pub server_name: ::std::option::Option<::std::string::String>,
    /// <p>Enables ongoing replication (CDC) as a BOOLEAN value. The default is true.</p>
    pub set_data_capture_changes: ::std::option::Option<bool>,
    /// <p>For ongoing replication (CDC), use CurrentLSN to specify a log sequence number (LSN) where you want the replication to start.</p>
    pub current_lsn: ::std::option::Option<::std::string::String>,
    /// <p>Maximum number of bytes per read, as a NUMBER value. The default is 64 KB.</p>
    pub max_k_bytes_per_read: ::std::option::Option<i32>,
    /// <p>Endpoint connection user name.</p>
    pub username: ::std::option::Option<::std::string::String>,
    /// <p>The full Amazon Resource Name (ARN) of the IAM role that specifies DMS as the trusted entity and grants the required permissions to access the value in <code>SecretsManagerSecret</code>. The role must allow the <code>iam:PassRole</code> action. <code>SecretsManagerSecret</code> has the value of the Amazon Web Services Secrets Manager secret that allows access to the Db2 LUW endpoint.</p><note>
    /// <p>You can specify one of two sets of values for these permissions. You can specify the values for this setting and <code>SecretsManagerSecretId</code>. Or you can specify clear-text values for <code>UserName</code>, <code>Password</code>, <code>ServerName</code>, and <code>Port</code>. You can't specify both. For more information on creating this <code>SecretsManagerSecret</code> and the <code>SecretsManagerAccessRoleArn</code> and <code>SecretsManagerSecretId</code> required to access it, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#security-iam-secretsmanager">Using secrets to access Database Migration Service resources</a> in the <i>Database Migration Service User Guide</i>.</p>
    /// </note>
    pub secrets_manager_access_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The full ARN, partial ARN, or friendly name of the <code>SecretsManagerSecret</code> that contains the Db2 LUW endpoint connection details.</p>
    pub secrets_manager_secret_id: ::std::option::Option<::std::string::String>,
    /// <p>The amount of time (in milliseconds) before DMS times out operations performed by DMS on the Db2 target. The default value is 1200 (20 minutes).</p>
    pub load_timeout: ::std::option::Option<i32>,
    /// <p>The size (in KB) of the in-memory file write buffer used when generating .csv files on the local disk on the DMS replication instance. The default value is 1024 (1 MB).</p>
    pub write_buffer_size: ::std::option::Option<i32>,
    /// <p>Specifies the maximum size (in KB) of .csv files used to transfer data to Db2 LUW.</p>
    pub max_file_size: ::std::option::Option<i32>,
    /// <p>If true, DMS saves any .csv files to the Db2 LUW target that were used to replicate data. DMS uses these files for analysis and troubleshooting.</p>
    /// <p>The default value is false.</p>
    pub keep_csv_files: ::std::option::Option<bool>,
}
impl IbmDb2Settings {
    /// <p>Database name for the endpoint.</p>
    pub fn database_name(&self) -> ::std::option::Option<&str> {
        self.database_name.as_deref()
    }
    /// <p>Endpoint connection password.</p>
    pub fn password(&self) -> ::std::option::Option<&str> {
        self.password.as_deref()
    }
    /// <p>Endpoint TCP port. The default value is 50000.</p>
    pub fn port(&self) -> ::std::option::Option<i32> {
        self.port
    }
    /// <p>Fully qualified domain name of the endpoint.</p>
    pub fn server_name(&self) -> ::std::option::Option<&str> {
        self.server_name.as_deref()
    }
    /// <p>Enables ongoing replication (CDC) as a BOOLEAN value. The default is true.</p>
    pub fn set_data_capture_changes(&self) -> ::std::option::Option<bool> {
        self.set_data_capture_changes
    }
    /// <p>For ongoing replication (CDC), use CurrentLSN to specify a log sequence number (LSN) where you want the replication to start.</p>
    pub fn current_lsn(&self) -> ::std::option::Option<&str> {
        self.current_lsn.as_deref()
    }
    /// <p>Maximum number of bytes per read, as a NUMBER value. The default is 64 KB.</p>
    pub fn max_k_bytes_per_read(&self) -> ::std::option::Option<i32> {
        self.max_k_bytes_per_read
    }
    /// <p>Endpoint connection user name.</p>
    pub fn username(&self) -> ::std::option::Option<&str> {
        self.username.as_deref()
    }
    /// <p>The full Amazon Resource Name (ARN) of the IAM role that specifies DMS as the trusted entity and grants the required permissions to access the value in <code>SecretsManagerSecret</code>. The role must allow the <code>iam:PassRole</code> action. <code>SecretsManagerSecret</code> has the value of the Amazon Web Services Secrets Manager secret that allows access to the Db2 LUW endpoint.</p><note>
    /// <p>You can specify one of two sets of values for these permissions. You can specify the values for this setting and <code>SecretsManagerSecretId</code>. Or you can specify clear-text values for <code>UserName</code>, <code>Password</code>, <code>ServerName</code>, and <code>Port</code>. You can't specify both. For more information on creating this <code>SecretsManagerSecret</code> and the <code>SecretsManagerAccessRoleArn</code> and <code>SecretsManagerSecretId</code> required to access it, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#security-iam-secretsmanager">Using secrets to access Database Migration Service resources</a> in the <i>Database Migration Service User Guide</i>.</p>
    /// </note>
    pub fn secrets_manager_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.secrets_manager_access_role_arn.as_deref()
    }
    /// <p>The full ARN, partial ARN, or friendly name of the <code>SecretsManagerSecret</code> that contains the Db2 LUW endpoint connection details.</p>
    pub fn secrets_manager_secret_id(&self) -> ::std::option::Option<&str> {
        self.secrets_manager_secret_id.as_deref()
    }
    /// <p>The amount of time (in milliseconds) before DMS times out operations performed by DMS on the Db2 target. The default value is 1200 (20 minutes).</p>
    pub fn load_timeout(&self) -> ::std::option::Option<i32> {
        self.load_timeout
    }
    /// <p>The size (in KB) of the in-memory file write buffer used when generating .csv files on the local disk on the DMS replication instance. The default value is 1024 (1 MB).</p>
    pub fn write_buffer_size(&self) -> ::std::option::Option<i32> {
        self.write_buffer_size
    }
    /// <p>Specifies the maximum size (in KB) of .csv files used to transfer data to Db2 LUW.</p>
    pub fn max_file_size(&self) -> ::std::option::Option<i32> {
        self.max_file_size
    }
    /// <p>If true, DMS saves any .csv files to the Db2 LUW target that were used to replicate data. DMS uses these files for analysis and troubleshooting.</p>
    /// <p>The default value is false.</p>
    pub fn keep_csv_files(&self) -> ::std::option::Option<bool> {
        self.keep_csv_files
    }
}
impl ::std::fmt::Debug for IbmDb2Settings {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IbmDb2Settings");
        formatter.field("database_name", &self.database_name);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("port", &self.port);
        formatter.field("server_name", &self.server_name);
        formatter.field("set_data_capture_changes", &self.set_data_capture_changes);
        formatter.field("current_lsn", &self.current_lsn);
        formatter.field("max_k_bytes_per_read", &self.max_k_bytes_per_read);
        formatter.field("username", &self.username);
        formatter.field("secrets_manager_access_role_arn", &self.secrets_manager_access_role_arn);
        formatter.field("secrets_manager_secret_id", &self.secrets_manager_secret_id);
        formatter.field("load_timeout", &self.load_timeout);
        formatter.field("write_buffer_size", &self.write_buffer_size);
        formatter.field("max_file_size", &self.max_file_size);
        formatter.field("keep_csv_files", &self.keep_csv_files);
        formatter.finish()
    }
}
impl IbmDb2Settings {
    /// Creates a new builder-style object to manufacture [`IbmDb2Settings`](crate::types::IbmDb2Settings).
    pub fn builder() -> crate::types::builders::IbmDb2SettingsBuilder {
        crate::types::builders::IbmDb2SettingsBuilder::default()
    }
}

/// A builder for [`IbmDb2Settings`](crate::types::IbmDb2Settings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct IbmDb2SettingsBuilder {
    pub(crate) database_name: ::std::option::Option<::std::string::String>,
    pub(crate) password: ::std::option::Option<::std::string::String>,
    pub(crate) port: ::std::option::Option<i32>,
    pub(crate) server_name: ::std::option::Option<::std::string::String>,
    pub(crate) set_data_capture_changes: ::std::option::Option<bool>,
    pub(crate) current_lsn: ::std::option::Option<::std::string::String>,
    pub(crate) max_k_bytes_per_read: ::std::option::Option<i32>,
    pub(crate) username: ::std::option::Option<::std::string::String>,
    pub(crate) secrets_manager_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) secrets_manager_secret_id: ::std::option::Option<::std::string::String>,
    pub(crate) load_timeout: ::std::option::Option<i32>,
    pub(crate) write_buffer_size: ::std::option::Option<i32>,
    pub(crate) max_file_size: ::std::option::Option<i32>,
    pub(crate) keep_csv_files: ::std::option::Option<bool>,
}
impl IbmDb2SettingsBuilder {
    /// <p>Database name for the endpoint.</p>
    pub fn database_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.database_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Database name for the endpoint.</p>
    pub fn set_database_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.database_name = input;
        self
    }
    /// <p>Database name for the endpoint.</p>
    pub fn get_database_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.database_name
    }
    /// <p>Endpoint connection password.</p>
    pub fn password(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.password = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Endpoint connection password.</p>
    pub fn set_password(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.password = input;
        self
    }
    /// <p>Endpoint connection password.</p>
    pub fn get_password(&self) -> &::std::option::Option<::std::string::String> {
        &self.password
    }
    /// <p>Endpoint TCP port. The default value is 50000.</p>
    pub fn port(mut self, input: i32) -> Self {
        self.port = ::std::option::Option::Some(input);
        self
    }
    /// <p>Endpoint TCP port. The default value is 50000.</p>
    pub fn set_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.port = input;
        self
    }
    /// <p>Endpoint TCP port. The default value is 50000.</p>
    pub fn get_port(&self) -> &::std::option::Option<i32> {
        &self.port
    }
    /// <p>Fully qualified domain name of the endpoint.</p>
    pub fn server_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.server_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Fully qualified domain name of the endpoint.</p>
    pub fn set_server_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.server_name = input;
        self
    }
    /// <p>Fully qualified domain name of the endpoint.</p>
    pub fn get_server_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.server_name
    }
    /// <p>Enables ongoing replication (CDC) as a BOOLEAN value. The default is true.</p>
    pub fn set_data_capture_changes(mut self, input: bool) -> Self {
        self.set_data_capture_changes = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enables ongoing replication (CDC) as a BOOLEAN value. The default is true.</p>
    pub fn set_set_data_capture_changes(mut self, input: ::std::option::Option<bool>) -> Self {
        self.set_data_capture_changes = input;
        self
    }
    /// <p>Enables ongoing replication (CDC) as a BOOLEAN value. The default is true.</p>
    pub fn get_set_data_capture_changes(&self) -> &::std::option::Option<bool> {
        &self.set_data_capture_changes
    }
    /// <p>For ongoing replication (CDC), use CurrentLSN to specify a log sequence number (LSN) where you want the replication to start.</p>
    pub fn current_lsn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.current_lsn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For ongoing replication (CDC), use CurrentLSN to specify a log sequence number (LSN) where you want the replication to start.</p>
    pub fn set_current_lsn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.current_lsn = input;
        self
    }
    /// <p>For ongoing replication (CDC), use CurrentLSN to specify a log sequence number (LSN) where you want the replication to start.</p>
    pub fn get_current_lsn(&self) -> &::std::option::Option<::std::string::String> {
        &self.current_lsn
    }
    /// <p>Maximum number of bytes per read, as a NUMBER value. The default is 64 KB.</p>
    pub fn max_k_bytes_per_read(mut self, input: i32) -> Self {
        self.max_k_bytes_per_read = ::std::option::Option::Some(input);
        self
    }
    /// <p>Maximum number of bytes per read, as a NUMBER value. The default is 64 KB.</p>
    pub fn set_max_k_bytes_per_read(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_k_bytes_per_read = input;
        self
    }
    /// <p>Maximum number of bytes per read, as a NUMBER value. The default is 64 KB.</p>
    pub fn get_max_k_bytes_per_read(&self) -> &::std::option::Option<i32> {
        &self.max_k_bytes_per_read
    }
    /// <p>Endpoint connection user name.</p>
    pub fn username(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.username = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Endpoint connection user name.</p>
    pub fn set_username(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.username = input;
        self
    }
    /// <p>Endpoint connection user name.</p>
    pub fn get_username(&self) -> &::std::option::Option<::std::string::String> {
        &self.username
    }
    /// <p>The full Amazon Resource Name (ARN) of the IAM role that specifies DMS as the trusted entity and grants the required permissions to access the value in <code>SecretsManagerSecret</code>. The role must allow the <code>iam:PassRole</code> action. <code>SecretsManagerSecret</code> has the value of the Amazon Web Services Secrets Manager secret that allows access to the Db2 LUW endpoint.</p><note>
    /// <p>You can specify one of two sets of values for these permissions. You can specify the values for this setting and <code>SecretsManagerSecretId</code>. Or you can specify clear-text values for <code>UserName</code>, <code>Password</code>, <code>ServerName</code>, and <code>Port</code>. You can't specify both. For more information on creating this <code>SecretsManagerSecret</code> and the <code>SecretsManagerAccessRoleArn</code> and <code>SecretsManagerSecretId</code> required to access it, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#security-iam-secretsmanager">Using secrets to access Database Migration Service resources</a> in the <i>Database Migration Service User Guide</i>.</p>
    /// </note>
    pub fn secrets_manager_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secrets_manager_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The full Amazon Resource Name (ARN) of the IAM role that specifies DMS as the trusted entity and grants the required permissions to access the value in <code>SecretsManagerSecret</code>. The role must allow the <code>iam:PassRole</code> action. <code>SecretsManagerSecret</code> has the value of the Amazon Web Services Secrets Manager secret that allows access to the Db2 LUW endpoint.</p><note>
    /// <p>You can specify one of two sets of values for these permissions. You can specify the values for this setting and <code>SecretsManagerSecretId</code>. Or you can specify clear-text values for <code>UserName</code>, <code>Password</code>, <code>ServerName</code>, and <code>Port</code>. You can't specify both. For more information on creating this <code>SecretsManagerSecret</code> and the <code>SecretsManagerAccessRoleArn</code> and <code>SecretsManagerSecretId</code> required to access it, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#security-iam-secretsmanager">Using secrets to access Database Migration Service resources</a> in the <i>Database Migration Service User Guide</i>.</p>
    /// </note>
    pub fn set_secrets_manager_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secrets_manager_access_role_arn = input;
        self
    }
    /// <p>The full Amazon Resource Name (ARN) of the IAM role that specifies DMS as the trusted entity and grants the required permissions to access the value in <code>SecretsManagerSecret</code>. The role must allow the <code>iam:PassRole</code> action. <code>SecretsManagerSecret</code> has the value of the Amazon Web Services Secrets Manager secret that allows access to the Db2 LUW endpoint.</p><note>
    /// <p>You can specify one of two sets of values for these permissions. You can specify the values for this setting and <code>SecretsManagerSecretId</code>. Or you can specify clear-text values for <code>UserName</code>, <code>Password</code>, <code>ServerName</code>, and <code>Port</code>. You can't specify both. For more information on creating this <code>SecretsManagerSecret</code> and the <code>SecretsManagerAccessRoleArn</code> and <code>SecretsManagerSecretId</code> required to access it, see <a href="https://docs.aws.amazon.com/dms/latest/userguide/CHAP_Security.html#security-iam-secretsmanager">Using secrets to access Database Migration Service resources</a> in the <i>Database Migration Service User Guide</i>.</p>
    /// </note>
    pub fn get_secrets_manager_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.secrets_manager_access_role_arn
    }
    /// <p>The full ARN, partial ARN, or friendly name of the <code>SecretsManagerSecret</code> that contains the Db2 LUW endpoint connection details.</p>
    pub fn secrets_manager_secret_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.secrets_manager_secret_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The full ARN, partial ARN, or friendly name of the <code>SecretsManagerSecret</code> that contains the Db2 LUW endpoint connection details.</p>
    pub fn set_secrets_manager_secret_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.secrets_manager_secret_id = input;
        self
    }
    /// <p>The full ARN, partial ARN, or friendly name of the <code>SecretsManagerSecret</code> that contains the Db2 LUW endpoint connection details.</p>
    pub fn get_secrets_manager_secret_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.secrets_manager_secret_id
    }
    /// <p>The amount of time (in milliseconds) before DMS times out operations performed by DMS on the Db2 target. The default value is 1200 (20 minutes).</p>
    pub fn load_timeout(mut self, input: i32) -> Self {
        self.load_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>The amount of time (in milliseconds) before DMS times out operations performed by DMS on the Db2 target. The default value is 1200 (20 minutes).</p>
    pub fn set_load_timeout(mut self, input: ::std::option::Option<i32>) -> Self {
        self.load_timeout = input;
        self
    }
    /// <p>The amount of time (in milliseconds) before DMS times out operations performed by DMS on the Db2 target. The default value is 1200 (20 minutes).</p>
    pub fn get_load_timeout(&self) -> &::std::option::Option<i32> {
        &self.load_timeout
    }
    /// <p>The size (in KB) of the in-memory file write buffer used when generating .csv files on the local disk on the DMS replication instance. The default value is 1024 (1 MB).</p>
    pub fn write_buffer_size(mut self, input: i32) -> Self {
        self.write_buffer_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>The size (in KB) of the in-memory file write buffer used when generating .csv files on the local disk on the DMS replication instance. The default value is 1024 (1 MB).</p>
    pub fn set_write_buffer_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.write_buffer_size = input;
        self
    }
    /// <p>The size (in KB) of the in-memory file write buffer used when generating .csv files on the local disk on the DMS replication instance. The default value is 1024 (1 MB).</p>
    pub fn get_write_buffer_size(&self) -> &::std::option::Option<i32> {
        &self.write_buffer_size
    }
    /// <p>Specifies the maximum size (in KB) of .csv files used to transfer data to Db2 LUW.</p>
    pub fn max_file_size(mut self, input: i32) -> Self {
        self.max_file_size = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the maximum size (in KB) of .csv files used to transfer data to Db2 LUW.</p>
    pub fn set_max_file_size(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_file_size = input;
        self
    }
    /// <p>Specifies the maximum size (in KB) of .csv files used to transfer data to Db2 LUW.</p>
    pub fn get_max_file_size(&self) -> &::std::option::Option<i32> {
        &self.max_file_size
    }
    /// <p>If true, DMS saves any .csv files to the Db2 LUW target that were used to replicate data. DMS uses these files for analysis and troubleshooting.</p>
    /// <p>The default value is false.</p>
    pub fn keep_csv_files(mut self, input: bool) -> Self {
        self.keep_csv_files = ::std::option::Option::Some(input);
        self
    }
    /// <p>If true, DMS saves any .csv files to the Db2 LUW target that were used to replicate data. DMS uses these files for analysis and troubleshooting.</p>
    /// <p>The default value is false.</p>
    pub fn set_keep_csv_files(mut self, input: ::std::option::Option<bool>) -> Self {
        self.keep_csv_files = input;
        self
    }
    /// <p>If true, DMS saves any .csv files to the Db2 LUW target that were used to replicate data. DMS uses these files for analysis and troubleshooting.</p>
    /// <p>The default value is false.</p>
    pub fn get_keep_csv_files(&self) -> &::std::option::Option<bool> {
        &self.keep_csv_files
    }
    /// Consumes the builder and constructs a [`IbmDb2Settings`](crate::types::IbmDb2Settings).
    pub fn build(self) -> crate::types::IbmDb2Settings {
        crate::types::IbmDb2Settings {
            database_name: self.database_name,
            password: self.password,
            port: self.port,
            server_name: self.server_name,
            set_data_capture_changes: self.set_data_capture_changes,
            current_lsn: self.current_lsn,
            max_k_bytes_per_read: self.max_k_bytes_per_read,
            username: self.username,
            secrets_manager_access_role_arn: self.secrets_manager_access_role_arn,
            secrets_manager_secret_id: self.secrets_manager_secret_id,
            load_timeout: self.load_timeout,
            write_buffer_size: self.write_buffer_size,
            max_file_size: self.max_file_size,
            keep_csv_files: self.keep_csv_files,
        }
    }
}
impl ::std::fmt::Debug for IbmDb2SettingsBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("IbmDb2SettingsBuilder");
        formatter.field("database_name", &self.database_name);
        formatter.field("password", &"*** Sensitive Data Redacted ***");
        formatter.field("port", &self.port);
        formatter.field("server_name", &self.server_name);
        formatter.field("set_data_capture_changes", &self.set_data_capture_changes);
        formatter.field("current_lsn", &self.current_lsn);
        formatter.field("max_k_bytes_per_read", &self.max_k_bytes_per_read);
        formatter.field("username", &self.username);
        formatter.field("secrets_manager_access_role_arn", &self.secrets_manager_access_role_arn);
        formatter.field("secrets_manager_secret_id", &self.secrets_manager_secret_id);
        formatter.field("load_timeout", &self.load_timeout);
        formatter.field("write_buffer_size", &self.write_buffer_size);
        formatter.field("max_file_size", &self.max_file_size);
        formatter.field("keep_csv_files", &self.keep_csv_files);
        formatter.finish()
    }
}
