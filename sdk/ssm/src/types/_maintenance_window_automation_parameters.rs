// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The parameters for an <code>AUTOMATION</code> task type.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MaintenanceWindowAutomationParameters {
    /// <p>The version of an Automation runbook to use during task execution.</p>
    pub document_version: ::std::option::Option<::std::string::String>,
    /// <p>The parameters for the <code>AUTOMATION</code> task.</p>
    /// <p>For information about specifying and updating task parameters, see <code>RegisterTaskWithMaintenanceWindow</code> and <code>UpdateMaintenanceWindowTask</code>.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p>For <code>AUTOMATION</code> task types, Amazon Web Services Systems Manager ignores any values specified for these parameters.</p>
    /// </note>
    pub parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
}
impl MaintenanceWindowAutomationParameters {
    /// <p>The version of an Automation runbook to use during task execution.</p>
    pub fn document_version(&self) -> ::std::option::Option<&str> {
        self.document_version.as_deref()
    }
    /// <p>The parameters for the <code>AUTOMATION</code> task.</p>
    /// <p>For information about specifying and updating task parameters, see <code>RegisterTaskWithMaintenanceWindow</code> and <code>UpdateMaintenanceWindowTask</code>.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p>For <code>AUTOMATION</code> task types, Amazon Web Services Systems Manager ignores any values specified for these parameters.</p>
    /// </note>
    pub fn parameters(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        self.parameters.as_ref()
    }
}
impl MaintenanceWindowAutomationParameters {
    /// Creates a new builder-style object to manufacture [`MaintenanceWindowAutomationParameters`](crate::types::MaintenanceWindowAutomationParameters).
    pub fn builder() -> crate::types::builders::MaintenanceWindowAutomationParametersBuilder {
        crate::types::builders::MaintenanceWindowAutomationParametersBuilder::default()
    }
}

/// A builder for [`MaintenanceWindowAutomationParameters`](crate::types::MaintenanceWindowAutomationParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MaintenanceWindowAutomationParametersBuilder {
    pub(crate) document_version: ::std::option::Option<::std::string::String>,
    pub(crate) parameters: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
}
impl MaintenanceWindowAutomationParametersBuilder {
    /// <p>The version of an Automation runbook to use during task execution.</p>
    pub fn document_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.document_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of an Automation runbook to use during task execution.</p>
    pub fn set_document_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.document_version = input;
        self
    }
    /// <p>The version of an Automation runbook to use during task execution.</p>
    pub fn get_document_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.document_version
    }
    /// Adds a key-value pair to `parameters`.
    ///
    /// To override the contents of this collection use [`set_parameters`](Self::set_parameters).
    ///
    /// <p>The parameters for the <code>AUTOMATION</code> task.</p>
    /// <p>For information about specifying and updating task parameters, see <code>RegisterTaskWithMaintenanceWindow</code> and <code>UpdateMaintenanceWindowTask</code>.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p>For <code>AUTOMATION</code> task types, Amazon Web Services Systems Manager ignores any values specified for these parameters.</p>
    /// </note>
    pub fn parameters(mut self, k: impl ::std::convert::Into<::std::string::String>, v: ::std::vec::Vec<::std::string::String>) -> Self {
        let mut hash_map = self.parameters.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.parameters = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The parameters for the <code>AUTOMATION</code> task.</p>
    /// <p>For information about specifying and updating task parameters, see <code>RegisterTaskWithMaintenanceWindow</code> and <code>UpdateMaintenanceWindowTask</code>.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p>For <code>AUTOMATION</code> task types, Amazon Web Services Systems Manager ignores any values specified for these parameters.</p>
    /// </note>
    pub fn set_parameters(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>>,
    ) -> Self {
        self.parameters = input;
        self
    }
    /// <p>The parameters for the <code>AUTOMATION</code> task.</p>
    /// <p>For information about specifying and updating task parameters, see <code>RegisterTaskWithMaintenanceWindow</code> and <code>UpdateMaintenanceWindowTask</code>.</p><note>
    /// <p><code>LoggingInfo</code> has been deprecated. To specify an Amazon Simple Storage Service (Amazon S3) bucket to contain logs, instead use the <code>OutputS3BucketName</code> and <code>OutputS3KeyPrefix</code> options in the <code>TaskInvocationParameters</code> structure. For information about how Amazon Web Services Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p><code>TaskParameters</code> has been deprecated. To specify parameters to pass to a task when it runs, instead use the <code>Parameters</code> option in the <code>TaskInvocationParameters</code> structure. For information about how Systems Manager handles these options for the supported maintenance window task types, see <code>MaintenanceWindowTaskInvocationParameters</code>.</p>
    /// <p>For <code>AUTOMATION</code> task types, Amazon Web Services Systems Manager ignores any values specified for these parameters.</p>
    /// </note>
    pub fn get_parameters(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::vec::Vec<::std::string::String>>> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`MaintenanceWindowAutomationParameters`](crate::types::MaintenanceWindowAutomationParameters).
    pub fn build(self) -> crate::types::MaintenanceWindowAutomationParameters {
        crate::types::MaintenanceWindowAutomationParameters {
            document_version: self.document_version,
            parameters: self.parameters,
        }
    }
}
