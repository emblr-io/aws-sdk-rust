// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration of the workgroup, which includes the location in Amazon S3 where query and calculation results are stored, the encryption option, if any, used for query and calculation results, whether the Amazon CloudWatch Metrics are enabled for the workgroup and whether workgroup settings override query settings, and the data usage limits for the amount of data scanned per query or per workgroup. The workgroup settings override is specified in <code>EnforceWorkGroupConfiguration</code> (true/false) in the <code>WorkGroupConfiguration</code>. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WorkGroupConfiguration {
    /// <p>The configuration for the workgroup, which includes the location in Amazon S3 where query and calculation results are stored and the encryption option, if any, used for query and calculation results. To run the query, you must specify the query results location using one of the ways: either in the workgroup using this setting, or for individual queries (client-side), using <code>ResultConfiguration$OutputLocation</code>. If none of them is set, Athena issues an error that no output location is provided.</p>
    pub result_configuration: ::std::option::Option<crate::types::ResultConfiguration>,
    /// <p>The configuration for storing results in Athena owned storage, which includes whether this feature is enabled; whether encryption configuration, if any, is used for encrypting query results.</p>
    pub managed_query_results_configuration: ::std::option::Option<crate::types::ManagedQueryResultsConfiguration>,
    /// <p>If set to "true", the settings for the workgroup override client-side settings. If set to "false", client-side settings are used. For more information, see <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub enforce_work_group_configuration: ::std::option::Option<bool>,
    /// <p>Indicates that the Amazon CloudWatch metrics are enabled for the workgroup.</p>
    pub publish_cloud_watch_metrics_enabled: ::std::option::Option<bool>,
    /// <p>The upper data usage limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan.</p>
    pub bytes_scanned_cutoff_per_query: ::std::option::Option<i64>,
    /// <p>If set to <code>true</code>, allows members assigned to a workgroup to reference Amazon S3 Requester Pays buckets in queries. If set to <code>false</code>, workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is <code>false</code>. For more information about Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html">Requester Pays Buckets</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    pub requester_pays_enabled: ::std::option::Option<bool>,
    /// <p>The engine version that all queries running on the workgroup use. Queries on the <code>AmazonAthenaPreviewFunctionality</code> workgroup run on the preview engine regardless of this setting.</p>
    pub engine_version: ::std::option::Option<crate::types::EngineVersion>,
    /// <p>Specifies a user defined JSON string that is passed to the notebook engine.</p>
    pub additional_configuration: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the execution role used to access user resources for Spark sessions and IAM Identity Center enabled workgroups. This property applies only to Spark enabled workgroups and IAM Identity Center enabled workgroups. The property is required for IAM Identity Center enabled workgroups.</p>
    pub execution_role: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the KMS key that is used to encrypt the user's data stores in Athena. This setting does not apply to Athena SQL workgroups.</p>
    pub customer_content_encryption_configuration: ::std::option::Option<crate::types::CustomerContentEncryptionConfiguration>,
    /// <p>Enforces a minimal level of encryption for the workgroup for query and calculation results that are written to Amazon S3. When enabled, workgroup users can set encryption only to the minimum level set by the administrator or higher when they submit queries.</p>
    /// <p>The <code>EnforceWorkGroupConfiguration</code> setting takes precedence over the <code>EnableMinimumEncryptionConfiguration</code> flag. This means that if <code>EnforceWorkGroupConfiguration</code> is true, the <code>EnableMinimumEncryptionConfiguration</code> flag is ignored, and the workgroup configuration for encryption is used.</p>
    pub enable_minimum_encryption_configuration: ::std::option::Option<bool>,
    /// <p>Specifies whether the workgroup is IAM Identity Center supported.</p>
    pub identity_center_configuration: ::std::option::Option<crate::types::IdentityCenterConfiguration>,
    /// <p>Specifies whether Amazon S3 access grants are enabled for query results.</p>
    pub query_results_s3_access_grants_configuration: ::std::option::Option<crate::types::QueryResultsS3AccessGrantsConfiguration>,
}
impl WorkGroupConfiguration {
    /// <p>The configuration for the workgroup, which includes the location in Amazon S3 where query and calculation results are stored and the encryption option, if any, used for query and calculation results. To run the query, you must specify the query results location using one of the ways: either in the workgroup using this setting, or for individual queries (client-side), using <code>ResultConfiguration$OutputLocation</code>. If none of them is set, Athena issues an error that no output location is provided.</p>
    pub fn result_configuration(&self) -> ::std::option::Option<&crate::types::ResultConfiguration> {
        self.result_configuration.as_ref()
    }
    /// <p>The configuration for storing results in Athena owned storage, which includes whether this feature is enabled; whether encryption configuration, if any, is used for encrypting query results.</p>
    pub fn managed_query_results_configuration(&self) -> ::std::option::Option<&crate::types::ManagedQueryResultsConfiguration> {
        self.managed_query_results_configuration.as_ref()
    }
    /// <p>If set to "true", the settings for the workgroup override client-side settings. If set to "false", client-side settings are used. For more information, see <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn enforce_work_group_configuration(&self) -> ::std::option::Option<bool> {
        self.enforce_work_group_configuration
    }
    /// <p>Indicates that the Amazon CloudWatch metrics are enabled for the workgroup.</p>
    pub fn publish_cloud_watch_metrics_enabled(&self) -> ::std::option::Option<bool> {
        self.publish_cloud_watch_metrics_enabled
    }
    /// <p>The upper data usage limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan.</p>
    pub fn bytes_scanned_cutoff_per_query(&self) -> ::std::option::Option<i64> {
        self.bytes_scanned_cutoff_per_query
    }
    /// <p>If set to <code>true</code>, allows members assigned to a workgroup to reference Amazon S3 Requester Pays buckets in queries. If set to <code>false</code>, workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is <code>false</code>. For more information about Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html">Requester Pays Buckets</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    pub fn requester_pays_enabled(&self) -> ::std::option::Option<bool> {
        self.requester_pays_enabled
    }
    /// <p>The engine version that all queries running on the workgroup use. Queries on the <code>AmazonAthenaPreviewFunctionality</code> workgroup run on the preview engine regardless of this setting.</p>
    pub fn engine_version(&self) -> ::std::option::Option<&crate::types::EngineVersion> {
        self.engine_version.as_ref()
    }
    /// <p>Specifies a user defined JSON string that is passed to the notebook engine.</p>
    pub fn additional_configuration(&self) -> ::std::option::Option<&str> {
        self.additional_configuration.as_deref()
    }
    /// <p>The ARN of the execution role used to access user resources for Spark sessions and IAM Identity Center enabled workgroups. This property applies only to Spark enabled workgroups and IAM Identity Center enabled workgroups. The property is required for IAM Identity Center enabled workgroups.</p>
    pub fn execution_role(&self) -> ::std::option::Option<&str> {
        self.execution_role.as_deref()
    }
    /// <p>Specifies the KMS key that is used to encrypt the user's data stores in Athena. This setting does not apply to Athena SQL workgroups.</p>
    pub fn customer_content_encryption_configuration(&self) -> ::std::option::Option<&crate::types::CustomerContentEncryptionConfiguration> {
        self.customer_content_encryption_configuration.as_ref()
    }
    /// <p>Enforces a minimal level of encryption for the workgroup for query and calculation results that are written to Amazon S3. When enabled, workgroup users can set encryption only to the minimum level set by the administrator or higher when they submit queries.</p>
    /// <p>The <code>EnforceWorkGroupConfiguration</code> setting takes precedence over the <code>EnableMinimumEncryptionConfiguration</code> flag. This means that if <code>EnforceWorkGroupConfiguration</code> is true, the <code>EnableMinimumEncryptionConfiguration</code> flag is ignored, and the workgroup configuration for encryption is used.</p>
    pub fn enable_minimum_encryption_configuration(&self) -> ::std::option::Option<bool> {
        self.enable_minimum_encryption_configuration
    }
    /// <p>Specifies whether the workgroup is IAM Identity Center supported.</p>
    pub fn identity_center_configuration(&self) -> ::std::option::Option<&crate::types::IdentityCenterConfiguration> {
        self.identity_center_configuration.as_ref()
    }
    /// <p>Specifies whether Amazon S3 access grants are enabled for query results.</p>
    pub fn query_results_s3_access_grants_configuration(&self) -> ::std::option::Option<&crate::types::QueryResultsS3AccessGrantsConfiguration> {
        self.query_results_s3_access_grants_configuration.as_ref()
    }
}
impl WorkGroupConfiguration {
    /// Creates a new builder-style object to manufacture [`WorkGroupConfiguration`](crate::types::WorkGroupConfiguration).
    pub fn builder() -> crate::types::builders::WorkGroupConfigurationBuilder {
        crate::types::builders::WorkGroupConfigurationBuilder::default()
    }
}

/// A builder for [`WorkGroupConfiguration`](crate::types::WorkGroupConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WorkGroupConfigurationBuilder {
    pub(crate) result_configuration: ::std::option::Option<crate::types::ResultConfiguration>,
    pub(crate) managed_query_results_configuration: ::std::option::Option<crate::types::ManagedQueryResultsConfiguration>,
    pub(crate) enforce_work_group_configuration: ::std::option::Option<bool>,
    pub(crate) publish_cloud_watch_metrics_enabled: ::std::option::Option<bool>,
    pub(crate) bytes_scanned_cutoff_per_query: ::std::option::Option<i64>,
    pub(crate) requester_pays_enabled: ::std::option::Option<bool>,
    pub(crate) engine_version: ::std::option::Option<crate::types::EngineVersion>,
    pub(crate) additional_configuration: ::std::option::Option<::std::string::String>,
    pub(crate) execution_role: ::std::option::Option<::std::string::String>,
    pub(crate) customer_content_encryption_configuration: ::std::option::Option<crate::types::CustomerContentEncryptionConfiguration>,
    pub(crate) enable_minimum_encryption_configuration: ::std::option::Option<bool>,
    pub(crate) identity_center_configuration: ::std::option::Option<crate::types::IdentityCenterConfiguration>,
    pub(crate) query_results_s3_access_grants_configuration: ::std::option::Option<crate::types::QueryResultsS3AccessGrantsConfiguration>,
}
impl WorkGroupConfigurationBuilder {
    /// <p>The configuration for the workgroup, which includes the location in Amazon S3 where query and calculation results are stored and the encryption option, if any, used for query and calculation results. To run the query, you must specify the query results location using one of the ways: either in the workgroup using this setting, or for individual queries (client-side), using <code>ResultConfiguration$OutputLocation</code>. If none of them is set, Athena issues an error that no output location is provided.</p>
    pub fn result_configuration(mut self, input: crate::types::ResultConfiguration) -> Self {
        self.result_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for the workgroup, which includes the location in Amazon S3 where query and calculation results are stored and the encryption option, if any, used for query and calculation results. To run the query, you must specify the query results location using one of the ways: either in the workgroup using this setting, or for individual queries (client-side), using <code>ResultConfiguration$OutputLocation</code>. If none of them is set, Athena issues an error that no output location is provided.</p>
    pub fn set_result_configuration(mut self, input: ::std::option::Option<crate::types::ResultConfiguration>) -> Self {
        self.result_configuration = input;
        self
    }
    /// <p>The configuration for the workgroup, which includes the location in Amazon S3 where query and calculation results are stored and the encryption option, if any, used for query and calculation results. To run the query, you must specify the query results location using one of the ways: either in the workgroup using this setting, or for individual queries (client-side), using <code>ResultConfiguration$OutputLocation</code>. If none of them is set, Athena issues an error that no output location is provided.</p>
    pub fn get_result_configuration(&self) -> &::std::option::Option<crate::types::ResultConfiguration> {
        &self.result_configuration
    }
    /// <p>The configuration for storing results in Athena owned storage, which includes whether this feature is enabled; whether encryption configuration, if any, is used for encrypting query results.</p>
    pub fn managed_query_results_configuration(mut self, input: crate::types::ManagedQueryResultsConfiguration) -> Self {
        self.managed_query_results_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for storing results in Athena owned storage, which includes whether this feature is enabled; whether encryption configuration, if any, is used for encrypting query results.</p>
    pub fn set_managed_query_results_configuration(mut self, input: ::std::option::Option<crate::types::ManagedQueryResultsConfiguration>) -> Self {
        self.managed_query_results_configuration = input;
        self
    }
    /// <p>The configuration for storing results in Athena owned storage, which includes whether this feature is enabled; whether encryption configuration, if any, is used for encrypting query results.</p>
    pub fn get_managed_query_results_configuration(&self) -> &::std::option::Option<crate::types::ManagedQueryResultsConfiguration> {
        &self.managed_query_results_configuration
    }
    /// <p>If set to "true", the settings for the workgroup override client-side settings. If set to "false", client-side settings are used. For more information, see <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn enforce_work_group_configuration(mut self, input: bool) -> Self {
        self.enforce_work_group_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to "true", the settings for the workgroup override client-side settings. If set to "false", client-side settings are used. For more information, see <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn set_enforce_work_group_configuration(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enforce_work_group_configuration = input;
        self
    }
    /// <p>If set to "true", the settings for the workgroup override client-side settings. If set to "false", client-side settings are used. For more information, see <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn get_enforce_work_group_configuration(&self) -> &::std::option::Option<bool> {
        &self.enforce_work_group_configuration
    }
    /// <p>Indicates that the Amazon CloudWatch metrics are enabled for the workgroup.</p>
    pub fn publish_cloud_watch_metrics_enabled(mut self, input: bool) -> Self {
        self.publish_cloud_watch_metrics_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates that the Amazon CloudWatch metrics are enabled for the workgroup.</p>
    pub fn set_publish_cloud_watch_metrics_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.publish_cloud_watch_metrics_enabled = input;
        self
    }
    /// <p>Indicates that the Amazon CloudWatch metrics are enabled for the workgroup.</p>
    pub fn get_publish_cloud_watch_metrics_enabled(&self) -> &::std::option::Option<bool> {
        &self.publish_cloud_watch_metrics_enabled
    }
    /// <p>The upper data usage limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan.</p>
    pub fn bytes_scanned_cutoff_per_query(mut self, input: i64) -> Self {
        self.bytes_scanned_cutoff_per_query = ::std::option::Option::Some(input);
        self
    }
    /// <p>The upper data usage limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan.</p>
    pub fn set_bytes_scanned_cutoff_per_query(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bytes_scanned_cutoff_per_query = input;
        self
    }
    /// <p>The upper data usage limit (cutoff) for the amount of bytes a single query in a workgroup is allowed to scan.</p>
    pub fn get_bytes_scanned_cutoff_per_query(&self) -> &::std::option::Option<i64> {
        &self.bytes_scanned_cutoff_per_query
    }
    /// <p>If set to <code>true</code>, allows members assigned to a workgroup to reference Amazon S3 Requester Pays buckets in queries. If set to <code>false</code>, workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is <code>false</code>. For more information about Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html">Requester Pays Buckets</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    pub fn requester_pays_enabled(mut self, input: bool) -> Self {
        self.requester_pays_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to <code>true</code>, allows members assigned to a workgroup to reference Amazon S3 Requester Pays buckets in queries. If set to <code>false</code>, workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is <code>false</code>. For more information about Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html">Requester Pays Buckets</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    pub fn set_requester_pays_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.requester_pays_enabled = input;
        self
    }
    /// <p>If set to <code>true</code>, allows members assigned to a workgroup to reference Amazon S3 Requester Pays buckets in queries. If set to <code>false</code>, workgroup members cannot query data from Requester Pays buckets, and queries that retrieve data from Requester Pays buckets cause an error. The default is <code>false</code>. For more information about Requester Pays buckets, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/RequesterPaysBuckets.html">Requester Pays Buckets</a> in the <i>Amazon Simple Storage Service Developer Guide</i>.</p>
    pub fn get_requester_pays_enabled(&self) -> &::std::option::Option<bool> {
        &self.requester_pays_enabled
    }
    /// <p>The engine version that all queries running on the workgroup use. Queries on the <code>AmazonAthenaPreviewFunctionality</code> workgroup run on the preview engine regardless of this setting.</p>
    pub fn engine_version(mut self, input: crate::types::EngineVersion) -> Self {
        self.engine_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The engine version that all queries running on the workgroup use. Queries on the <code>AmazonAthenaPreviewFunctionality</code> workgroup run on the preview engine regardless of this setting.</p>
    pub fn set_engine_version(mut self, input: ::std::option::Option<crate::types::EngineVersion>) -> Self {
        self.engine_version = input;
        self
    }
    /// <p>The engine version that all queries running on the workgroup use. Queries on the <code>AmazonAthenaPreviewFunctionality</code> workgroup run on the preview engine regardless of this setting.</p>
    pub fn get_engine_version(&self) -> &::std::option::Option<crate::types::EngineVersion> {
        &self.engine_version
    }
    /// <p>Specifies a user defined JSON string that is passed to the notebook engine.</p>
    pub fn additional_configuration(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.additional_configuration = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a user defined JSON string that is passed to the notebook engine.</p>
    pub fn set_additional_configuration(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.additional_configuration = input;
        self
    }
    /// <p>Specifies a user defined JSON string that is passed to the notebook engine.</p>
    pub fn get_additional_configuration(&self) -> &::std::option::Option<::std::string::String> {
        &self.additional_configuration
    }
    /// <p>The ARN of the execution role used to access user resources for Spark sessions and IAM Identity Center enabled workgroups. This property applies only to Spark enabled workgroups and IAM Identity Center enabled workgroups. The property is required for IAM Identity Center enabled workgroups.</p>
    pub fn execution_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.execution_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the execution role used to access user resources for Spark sessions and IAM Identity Center enabled workgroups. This property applies only to Spark enabled workgroups and IAM Identity Center enabled workgroups. The property is required for IAM Identity Center enabled workgroups.</p>
    pub fn set_execution_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.execution_role = input;
        self
    }
    /// <p>The ARN of the execution role used to access user resources for Spark sessions and IAM Identity Center enabled workgroups. This property applies only to Spark enabled workgroups and IAM Identity Center enabled workgroups. The property is required for IAM Identity Center enabled workgroups.</p>
    pub fn get_execution_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.execution_role
    }
    /// <p>Specifies the KMS key that is used to encrypt the user's data stores in Athena. This setting does not apply to Athena SQL workgroups.</p>
    pub fn customer_content_encryption_configuration(mut self, input: crate::types::CustomerContentEncryptionConfiguration) -> Self {
        self.customer_content_encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the KMS key that is used to encrypt the user's data stores in Athena. This setting does not apply to Athena SQL workgroups.</p>
    pub fn set_customer_content_encryption_configuration(
        mut self,
        input: ::std::option::Option<crate::types::CustomerContentEncryptionConfiguration>,
    ) -> Self {
        self.customer_content_encryption_configuration = input;
        self
    }
    /// <p>Specifies the KMS key that is used to encrypt the user's data stores in Athena. This setting does not apply to Athena SQL workgroups.</p>
    pub fn get_customer_content_encryption_configuration(&self) -> &::std::option::Option<crate::types::CustomerContentEncryptionConfiguration> {
        &self.customer_content_encryption_configuration
    }
    /// <p>Enforces a minimal level of encryption for the workgroup for query and calculation results that are written to Amazon S3. When enabled, workgroup users can set encryption only to the minimum level set by the administrator or higher when they submit queries.</p>
    /// <p>The <code>EnforceWorkGroupConfiguration</code> setting takes precedence over the <code>EnableMinimumEncryptionConfiguration</code> flag. This means that if <code>EnforceWorkGroupConfiguration</code> is true, the <code>EnableMinimumEncryptionConfiguration</code> flag is ignored, and the workgroup configuration for encryption is used.</p>
    pub fn enable_minimum_encryption_configuration(mut self, input: bool) -> Self {
        self.enable_minimum_encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Enforces a minimal level of encryption for the workgroup for query and calculation results that are written to Amazon S3. When enabled, workgroup users can set encryption only to the minimum level set by the administrator or higher when they submit queries.</p>
    /// <p>The <code>EnforceWorkGroupConfiguration</code> setting takes precedence over the <code>EnableMinimumEncryptionConfiguration</code> flag. This means that if <code>EnforceWorkGroupConfiguration</code> is true, the <code>EnableMinimumEncryptionConfiguration</code> flag is ignored, and the workgroup configuration for encryption is used.</p>
    pub fn set_enable_minimum_encryption_configuration(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_minimum_encryption_configuration = input;
        self
    }
    /// <p>Enforces a minimal level of encryption for the workgroup for query and calculation results that are written to Amazon S3. When enabled, workgroup users can set encryption only to the minimum level set by the administrator or higher when they submit queries.</p>
    /// <p>The <code>EnforceWorkGroupConfiguration</code> setting takes precedence over the <code>EnableMinimumEncryptionConfiguration</code> flag. This means that if <code>EnforceWorkGroupConfiguration</code> is true, the <code>EnableMinimumEncryptionConfiguration</code> flag is ignored, and the workgroup configuration for encryption is used.</p>
    pub fn get_enable_minimum_encryption_configuration(&self) -> &::std::option::Option<bool> {
        &self.enable_minimum_encryption_configuration
    }
    /// <p>Specifies whether the workgroup is IAM Identity Center supported.</p>
    pub fn identity_center_configuration(mut self, input: crate::types::IdentityCenterConfiguration) -> Self {
        self.identity_center_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the workgroup is IAM Identity Center supported.</p>
    pub fn set_identity_center_configuration(mut self, input: ::std::option::Option<crate::types::IdentityCenterConfiguration>) -> Self {
        self.identity_center_configuration = input;
        self
    }
    /// <p>Specifies whether the workgroup is IAM Identity Center supported.</p>
    pub fn get_identity_center_configuration(&self) -> &::std::option::Option<crate::types::IdentityCenterConfiguration> {
        &self.identity_center_configuration
    }
    /// <p>Specifies whether Amazon S3 access grants are enabled for query results.</p>
    pub fn query_results_s3_access_grants_configuration(mut self, input: crate::types::QueryResultsS3AccessGrantsConfiguration) -> Self {
        self.query_results_s3_access_grants_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether Amazon S3 access grants are enabled for query results.</p>
    pub fn set_query_results_s3_access_grants_configuration(
        mut self,
        input: ::std::option::Option<crate::types::QueryResultsS3AccessGrantsConfiguration>,
    ) -> Self {
        self.query_results_s3_access_grants_configuration = input;
        self
    }
    /// <p>Specifies whether Amazon S3 access grants are enabled for query results.</p>
    pub fn get_query_results_s3_access_grants_configuration(&self) -> &::std::option::Option<crate::types::QueryResultsS3AccessGrantsConfiguration> {
        &self.query_results_s3_access_grants_configuration
    }
    /// Consumes the builder and constructs a [`WorkGroupConfiguration`](crate::types::WorkGroupConfiguration).
    pub fn build(self) -> crate::types::WorkGroupConfiguration {
        crate::types::WorkGroupConfiguration {
            result_configuration: self.result_configuration,
            managed_query_results_configuration: self.managed_query_results_configuration,
            enforce_work_group_configuration: self.enforce_work_group_configuration,
            publish_cloud_watch_metrics_enabled: self.publish_cloud_watch_metrics_enabled,
            bytes_scanned_cutoff_per_query: self.bytes_scanned_cutoff_per_query,
            requester_pays_enabled: self.requester_pays_enabled,
            engine_version: self.engine_version,
            additional_configuration: self.additional_configuration,
            execution_role: self.execution_role,
            customer_content_encryption_configuration: self.customer_content_encryption_configuration,
            enable_minimum_encryption_configuration: self.enable_minimum_encryption_configuration,
            identity_center_configuration: self.identity_center_configuration,
            query_results_s3_access_grants_configuration: self.query_results_s3_access_grants_configuration,
        }
    }
}
