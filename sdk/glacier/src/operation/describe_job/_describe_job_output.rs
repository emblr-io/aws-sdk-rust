// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the description of an Amazon S3 Glacier job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeJobOutput {
    /// <p>An opaque string that identifies an Amazon S3 Glacier job.</p>
    pub job_id: ::std::option::Option<::std::string::String>,
    /// <p>The job description provided when initiating the job.</p>
    pub job_description: ::std::option::Option<::std::string::String>,
    /// <p>The job type. This value is either <code>ArchiveRetrieval</code>, <code>InventoryRetrieval</code>, or <code>Select</code>.</p>
    pub action: ::std::option::Option<crate::types::ActionCode>,
    /// <p>The archive ID requested for a select job or archive retrieval. Otherwise, this field is null.</p>
    pub archive_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the vault from which an archive retrieval was requested.</p>
    pub vault_arn: ::std::option::Option<::std::string::String>,
    /// <p>The UTC date when the job was created. This value is a string representation of ISO 8601 date format, for example <code>"2012-03-20T17:03:43.221Z"</code>.</p>
    pub creation_date: ::std::option::Option<::std::string::String>,
    /// <p>The job status. When a job is completed, you get the job's output using Get Job Output (GET output).</p>
    pub completed: bool,
    /// <p>The status code can be <code>InProgress</code>, <code>Succeeded</code>, or <code>Failed</code>, and indicates the status of the job.</p>
    pub status_code: ::std::option::Option<crate::types::StatusCode>,
    /// <p>A friendly message that describes the job status.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>For an archive retrieval job, this value is the size in bytes of the archive being requested for download. For an inventory retrieval or select job, this value is null.</p>
    pub archive_size_in_bytes: ::std::option::Option<i64>,
    /// <p>For an inventory retrieval job, this value is the size in bytes of the inventory requested for download. For an archive retrieval or select job, this value is null.</p>
    pub inventory_size_in_bytes: ::std::option::Option<i64>,
    /// <p>An Amazon SNS topic that receives notification.</p>
    pub sns_topic: ::std::option::Option<::std::string::String>,
    /// <p>The UTC time that the job request completed. While the job is in progress, the value is null.</p>
    pub completion_date: ::std::option::Option<::std::string::String>,
    /// <p>For an archive retrieval job, this value is the checksum of the archive. Otherwise, this value is null.</p>
    /// <p>The SHA256 tree hash value for the requested range of an archive. If the <b>InitiateJob</b> request for an archive specified a tree-hash aligned range, then this field returns a value.</p>
    /// <p>If the whole archive is retrieved, this value is the same as the ArchiveSHA256TreeHash value.</p>
    /// <p>This field is null for the following:</p>
    /// <ul>
    /// <li>
    /// <p>Archive retrieval jobs that specify a range that is not tree-hash aligned</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Archival jobs that specify a range that is equal to the whole archive, when the job status is <code>InProgress</code></p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Inventory jobs</p></li>
    /// <li>
    /// <p>Select jobs</p></li>
    /// </ul>
    pub sha256_tree_hash: ::std::option::Option<::std::string::String>,
    /// <p>The SHA256 tree hash of the entire archive for an archive retrieval. For inventory retrieval or select jobs, this field is null.</p>
    pub archive_sha256_tree_hash: ::std::option::Option<::std::string::String>,
    /// <p>The retrieved byte range for archive retrieval jobs in the form <i>StartByteValue</i>-<i>EndByteValue</i>. If no range was specified in the archive retrieval, then the whole archive is retrieved. In this case, <i>StartByteValue</i> equals 0 and <i>EndByteValue</i> equals the size of the archive minus 1. For inventory retrieval or select jobs, this field is null.</p>
    pub retrieval_byte_range: ::std::option::Option<::std::string::String>,
    /// <p>The tier to use for a select or an archive retrieval. Valid values are <code>Expedited</code>, <code>Standard</code>, or <code>Bulk</code>. <code>Standard</code> is the default.</p>
    pub tier: ::std::option::Option<::std::string::String>,
    /// <p>Parameters used for range inventory retrieval.</p>
    pub inventory_retrieval_parameters: ::std::option::Option<crate::types::InventoryRetrievalJobDescription>,
    /// <p>Contains the job output location.</p>
    pub job_output_path: ::std::option::Option<::std::string::String>,
    /// <p>Contains the parameters used for a select.</p>
    pub select_parameters: ::std::option::Option<crate::types::SelectParameters>,
    /// <p>Contains the location where the data from the select job is stored.</p>
    pub output_location: ::std::option::Option<crate::types::OutputLocation>,
    _request_id: Option<String>,
}
impl DescribeJobOutput {
    /// <p>An opaque string that identifies an Amazon S3 Glacier job.</p>
    pub fn job_id(&self) -> ::std::option::Option<&str> {
        self.job_id.as_deref()
    }
    /// <p>The job description provided when initiating the job.</p>
    pub fn job_description(&self) -> ::std::option::Option<&str> {
        self.job_description.as_deref()
    }
    /// <p>The job type. This value is either <code>ArchiveRetrieval</code>, <code>InventoryRetrieval</code>, or <code>Select</code>.</p>
    pub fn action(&self) -> ::std::option::Option<&crate::types::ActionCode> {
        self.action.as_ref()
    }
    /// <p>The archive ID requested for a select job or archive retrieval. Otherwise, this field is null.</p>
    pub fn archive_id(&self) -> ::std::option::Option<&str> {
        self.archive_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the vault from which an archive retrieval was requested.</p>
    pub fn vault_arn(&self) -> ::std::option::Option<&str> {
        self.vault_arn.as_deref()
    }
    /// <p>The UTC date when the job was created. This value is a string representation of ISO 8601 date format, for example <code>"2012-03-20T17:03:43.221Z"</code>.</p>
    pub fn creation_date(&self) -> ::std::option::Option<&str> {
        self.creation_date.as_deref()
    }
    /// <p>The job status. When a job is completed, you get the job's output using Get Job Output (GET output).</p>
    pub fn completed(&self) -> bool {
        self.completed
    }
    /// <p>The status code can be <code>InProgress</code>, <code>Succeeded</code>, or <code>Failed</code>, and indicates the status of the job.</p>
    pub fn status_code(&self) -> ::std::option::Option<&crate::types::StatusCode> {
        self.status_code.as_ref()
    }
    /// <p>A friendly message that describes the job status.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>For an archive retrieval job, this value is the size in bytes of the archive being requested for download. For an inventory retrieval or select job, this value is null.</p>
    pub fn archive_size_in_bytes(&self) -> ::std::option::Option<i64> {
        self.archive_size_in_bytes
    }
    /// <p>For an inventory retrieval job, this value is the size in bytes of the inventory requested for download. For an archive retrieval or select job, this value is null.</p>
    pub fn inventory_size_in_bytes(&self) -> ::std::option::Option<i64> {
        self.inventory_size_in_bytes
    }
    /// <p>An Amazon SNS topic that receives notification.</p>
    pub fn sns_topic(&self) -> ::std::option::Option<&str> {
        self.sns_topic.as_deref()
    }
    /// <p>The UTC time that the job request completed. While the job is in progress, the value is null.</p>
    pub fn completion_date(&self) -> ::std::option::Option<&str> {
        self.completion_date.as_deref()
    }
    /// <p>For an archive retrieval job, this value is the checksum of the archive. Otherwise, this value is null.</p>
    /// <p>The SHA256 tree hash value for the requested range of an archive. If the <b>InitiateJob</b> request for an archive specified a tree-hash aligned range, then this field returns a value.</p>
    /// <p>If the whole archive is retrieved, this value is the same as the ArchiveSHA256TreeHash value.</p>
    /// <p>This field is null for the following:</p>
    /// <ul>
    /// <li>
    /// <p>Archive retrieval jobs that specify a range that is not tree-hash aligned</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Archival jobs that specify a range that is equal to the whole archive, when the job status is <code>InProgress</code></p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Inventory jobs</p></li>
    /// <li>
    /// <p>Select jobs</p></li>
    /// </ul>
    pub fn sha256_tree_hash(&self) -> ::std::option::Option<&str> {
        self.sha256_tree_hash.as_deref()
    }
    /// <p>The SHA256 tree hash of the entire archive for an archive retrieval. For inventory retrieval or select jobs, this field is null.</p>
    pub fn archive_sha256_tree_hash(&self) -> ::std::option::Option<&str> {
        self.archive_sha256_tree_hash.as_deref()
    }
    /// <p>The retrieved byte range for archive retrieval jobs in the form <i>StartByteValue</i>-<i>EndByteValue</i>. If no range was specified in the archive retrieval, then the whole archive is retrieved. In this case, <i>StartByteValue</i> equals 0 and <i>EndByteValue</i> equals the size of the archive minus 1. For inventory retrieval or select jobs, this field is null.</p>
    pub fn retrieval_byte_range(&self) -> ::std::option::Option<&str> {
        self.retrieval_byte_range.as_deref()
    }
    /// <p>The tier to use for a select or an archive retrieval. Valid values are <code>Expedited</code>, <code>Standard</code>, or <code>Bulk</code>. <code>Standard</code> is the default.</p>
    pub fn tier(&self) -> ::std::option::Option<&str> {
        self.tier.as_deref()
    }
    /// <p>Parameters used for range inventory retrieval.</p>
    pub fn inventory_retrieval_parameters(&self) -> ::std::option::Option<&crate::types::InventoryRetrievalJobDescription> {
        self.inventory_retrieval_parameters.as_ref()
    }
    /// <p>Contains the job output location.</p>
    pub fn job_output_path(&self) -> ::std::option::Option<&str> {
        self.job_output_path.as_deref()
    }
    /// <p>Contains the parameters used for a select.</p>
    pub fn select_parameters(&self) -> ::std::option::Option<&crate::types::SelectParameters> {
        self.select_parameters.as_ref()
    }
    /// <p>Contains the location where the data from the select job is stored.</p>
    pub fn output_location(&self) -> ::std::option::Option<&crate::types::OutputLocation> {
        self.output_location.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeJobOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeJobOutput {
    /// Creates a new builder-style object to manufacture [`DescribeJobOutput`](crate::operation::describe_job::DescribeJobOutput).
    pub fn builder() -> crate::operation::describe_job::builders::DescribeJobOutputBuilder {
        crate::operation::describe_job::builders::DescribeJobOutputBuilder::default()
    }
}

/// A builder for [`DescribeJobOutput`](crate::operation::describe_job::DescribeJobOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeJobOutputBuilder {
    pub(crate) job_id: ::std::option::Option<::std::string::String>,
    pub(crate) job_description: ::std::option::Option<::std::string::String>,
    pub(crate) action: ::std::option::Option<crate::types::ActionCode>,
    pub(crate) archive_id: ::std::option::Option<::std::string::String>,
    pub(crate) vault_arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date: ::std::option::Option<::std::string::String>,
    pub(crate) completed: ::std::option::Option<bool>,
    pub(crate) status_code: ::std::option::Option<crate::types::StatusCode>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) archive_size_in_bytes: ::std::option::Option<i64>,
    pub(crate) inventory_size_in_bytes: ::std::option::Option<i64>,
    pub(crate) sns_topic: ::std::option::Option<::std::string::String>,
    pub(crate) completion_date: ::std::option::Option<::std::string::String>,
    pub(crate) sha256_tree_hash: ::std::option::Option<::std::string::String>,
    pub(crate) archive_sha256_tree_hash: ::std::option::Option<::std::string::String>,
    pub(crate) retrieval_byte_range: ::std::option::Option<::std::string::String>,
    pub(crate) tier: ::std::option::Option<::std::string::String>,
    pub(crate) inventory_retrieval_parameters: ::std::option::Option<crate::types::InventoryRetrievalJobDescription>,
    pub(crate) job_output_path: ::std::option::Option<::std::string::String>,
    pub(crate) select_parameters: ::std::option::Option<crate::types::SelectParameters>,
    pub(crate) output_location: ::std::option::Option<crate::types::OutputLocation>,
    _request_id: Option<String>,
}
impl DescribeJobOutputBuilder {
    /// <p>An opaque string that identifies an Amazon S3 Glacier job.</p>
    pub fn job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An opaque string that identifies an Amazon S3 Glacier job.</p>
    pub fn set_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_id = input;
        self
    }
    /// <p>An opaque string that identifies an Amazon S3 Glacier job.</p>
    pub fn get_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_id
    }
    /// <p>The job description provided when initiating the job.</p>
    pub fn job_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job description provided when initiating the job.</p>
    pub fn set_job_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_description = input;
        self
    }
    /// <p>The job description provided when initiating the job.</p>
    pub fn get_job_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_description
    }
    /// <p>The job type. This value is either <code>ArchiveRetrieval</code>, <code>InventoryRetrieval</code>, or <code>Select</code>.</p>
    pub fn action(mut self, input: crate::types::ActionCode) -> Self {
        self.action = ::std::option::Option::Some(input);
        self
    }
    /// <p>The job type. This value is either <code>ArchiveRetrieval</code>, <code>InventoryRetrieval</code>, or <code>Select</code>.</p>
    pub fn set_action(mut self, input: ::std::option::Option<crate::types::ActionCode>) -> Self {
        self.action = input;
        self
    }
    /// <p>The job type. This value is either <code>ArchiveRetrieval</code>, <code>InventoryRetrieval</code>, or <code>Select</code>.</p>
    pub fn get_action(&self) -> &::std::option::Option<crate::types::ActionCode> {
        &self.action
    }
    /// <p>The archive ID requested for a select job or archive retrieval. Otherwise, this field is null.</p>
    pub fn archive_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.archive_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The archive ID requested for a select job or archive retrieval. Otherwise, this field is null.</p>
    pub fn set_archive_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.archive_id = input;
        self
    }
    /// <p>The archive ID requested for a select job or archive retrieval. Otherwise, this field is null.</p>
    pub fn get_archive_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.archive_id
    }
    /// <p>The Amazon Resource Name (ARN) of the vault from which an archive retrieval was requested.</p>
    pub fn vault_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vault_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the vault from which an archive retrieval was requested.</p>
    pub fn set_vault_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vault_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the vault from which an archive retrieval was requested.</p>
    pub fn get_vault_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.vault_arn
    }
    /// <p>The UTC date when the job was created. This value is a string representation of ISO 8601 date format, for example <code>"2012-03-20T17:03:43.221Z"</code>.</p>
    pub fn creation_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.creation_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The UTC date when the job was created. This value is a string representation of ISO 8601 date format, for example <code>"2012-03-20T17:03:43.221Z"</code>.</p>
    pub fn set_creation_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.creation_date = input;
        self
    }
    /// <p>The UTC date when the job was created. This value is a string representation of ISO 8601 date format, for example <code>"2012-03-20T17:03:43.221Z"</code>.</p>
    pub fn get_creation_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.creation_date
    }
    /// <p>The job status. When a job is completed, you get the job's output using Get Job Output (GET output).</p>
    pub fn completed(mut self, input: bool) -> Self {
        self.completed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The job status. When a job is completed, you get the job's output using Get Job Output (GET output).</p>
    pub fn set_completed(mut self, input: ::std::option::Option<bool>) -> Self {
        self.completed = input;
        self
    }
    /// <p>The job status. When a job is completed, you get the job's output using Get Job Output (GET output).</p>
    pub fn get_completed(&self) -> &::std::option::Option<bool> {
        &self.completed
    }
    /// <p>The status code can be <code>InProgress</code>, <code>Succeeded</code>, or <code>Failed</code>, and indicates the status of the job.</p>
    pub fn status_code(mut self, input: crate::types::StatusCode) -> Self {
        self.status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status code can be <code>InProgress</code>, <code>Succeeded</code>, or <code>Failed</code>, and indicates the status of the job.</p>
    pub fn set_status_code(mut self, input: ::std::option::Option<crate::types::StatusCode>) -> Self {
        self.status_code = input;
        self
    }
    /// <p>The status code can be <code>InProgress</code>, <code>Succeeded</code>, or <code>Failed</code>, and indicates the status of the job.</p>
    pub fn get_status_code(&self) -> &::std::option::Option<crate::types::StatusCode> {
        &self.status_code
    }
    /// <p>A friendly message that describes the job status.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A friendly message that describes the job status.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>A friendly message that describes the job status.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>For an archive retrieval job, this value is the size in bytes of the archive being requested for download. For an inventory retrieval or select job, this value is null.</p>
    pub fn archive_size_in_bytes(mut self, input: i64) -> Self {
        self.archive_size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>For an archive retrieval job, this value is the size in bytes of the archive being requested for download. For an inventory retrieval or select job, this value is null.</p>
    pub fn set_archive_size_in_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.archive_size_in_bytes = input;
        self
    }
    /// <p>For an archive retrieval job, this value is the size in bytes of the archive being requested for download. For an inventory retrieval or select job, this value is null.</p>
    pub fn get_archive_size_in_bytes(&self) -> &::std::option::Option<i64> {
        &self.archive_size_in_bytes
    }
    /// <p>For an inventory retrieval job, this value is the size in bytes of the inventory requested for download. For an archive retrieval or select job, this value is null.</p>
    pub fn inventory_size_in_bytes(mut self, input: i64) -> Self {
        self.inventory_size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>For an inventory retrieval job, this value is the size in bytes of the inventory requested for download. For an archive retrieval or select job, this value is null.</p>
    pub fn set_inventory_size_in_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.inventory_size_in_bytes = input;
        self
    }
    /// <p>For an inventory retrieval job, this value is the size in bytes of the inventory requested for download. For an archive retrieval or select job, this value is null.</p>
    pub fn get_inventory_size_in_bytes(&self) -> &::std::option::Option<i64> {
        &self.inventory_size_in_bytes
    }
    /// <p>An Amazon SNS topic that receives notification.</p>
    pub fn sns_topic(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sns_topic = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon SNS topic that receives notification.</p>
    pub fn set_sns_topic(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sns_topic = input;
        self
    }
    /// <p>An Amazon SNS topic that receives notification.</p>
    pub fn get_sns_topic(&self) -> &::std::option::Option<::std::string::String> {
        &self.sns_topic
    }
    /// <p>The UTC time that the job request completed. While the job is in progress, the value is null.</p>
    pub fn completion_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.completion_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The UTC time that the job request completed. While the job is in progress, the value is null.</p>
    pub fn set_completion_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.completion_date = input;
        self
    }
    /// <p>The UTC time that the job request completed. While the job is in progress, the value is null.</p>
    pub fn get_completion_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.completion_date
    }
    /// <p>For an archive retrieval job, this value is the checksum of the archive. Otherwise, this value is null.</p>
    /// <p>The SHA256 tree hash value for the requested range of an archive. If the <b>InitiateJob</b> request for an archive specified a tree-hash aligned range, then this field returns a value.</p>
    /// <p>If the whole archive is retrieved, this value is the same as the ArchiveSHA256TreeHash value.</p>
    /// <p>This field is null for the following:</p>
    /// <ul>
    /// <li>
    /// <p>Archive retrieval jobs that specify a range that is not tree-hash aligned</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Archival jobs that specify a range that is equal to the whole archive, when the job status is <code>InProgress</code></p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Inventory jobs</p></li>
    /// <li>
    /// <p>Select jobs</p></li>
    /// </ul>
    pub fn sha256_tree_hash(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.sha256_tree_hash = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>For an archive retrieval job, this value is the checksum of the archive. Otherwise, this value is null.</p>
    /// <p>The SHA256 tree hash value for the requested range of an archive. If the <b>InitiateJob</b> request for an archive specified a tree-hash aligned range, then this field returns a value.</p>
    /// <p>If the whole archive is retrieved, this value is the same as the ArchiveSHA256TreeHash value.</p>
    /// <p>This field is null for the following:</p>
    /// <ul>
    /// <li>
    /// <p>Archive retrieval jobs that specify a range that is not tree-hash aligned</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Archival jobs that specify a range that is equal to the whole archive, when the job status is <code>InProgress</code></p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Inventory jobs</p></li>
    /// <li>
    /// <p>Select jobs</p></li>
    /// </ul>
    pub fn set_sha256_tree_hash(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.sha256_tree_hash = input;
        self
    }
    /// <p>For an archive retrieval job, this value is the checksum of the archive. Otherwise, this value is null.</p>
    /// <p>The SHA256 tree hash value for the requested range of an archive. If the <b>InitiateJob</b> request for an archive specified a tree-hash aligned range, then this field returns a value.</p>
    /// <p>If the whole archive is retrieved, this value is the same as the ArchiveSHA256TreeHash value.</p>
    /// <p>This field is null for the following:</p>
    /// <ul>
    /// <li>
    /// <p>Archive retrieval jobs that specify a range that is not tree-hash aligned</p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Archival jobs that specify a range that is equal to the whole archive, when the job status is <code>InProgress</code></p></li>
    /// </ul>
    /// <ul>
    /// <li>
    /// <p>Inventory jobs</p></li>
    /// <li>
    /// <p>Select jobs</p></li>
    /// </ul>
    pub fn get_sha256_tree_hash(&self) -> &::std::option::Option<::std::string::String> {
        &self.sha256_tree_hash
    }
    /// <p>The SHA256 tree hash of the entire archive for an archive retrieval. For inventory retrieval or select jobs, this field is null.</p>
    pub fn archive_sha256_tree_hash(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.archive_sha256_tree_hash = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The SHA256 tree hash of the entire archive for an archive retrieval. For inventory retrieval or select jobs, this field is null.</p>
    pub fn set_archive_sha256_tree_hash(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.archive_sha256_tree_hash = input;
        self
    }
    /// <p>The SHA256 tree hash of the entire archive for an archive retrieval. For inventory retrieval or select jobs, this field is null.</p>
    pub fn get_archive_sha256_tree_hash(&self) -> &::std::option::Option<::std::string::String> {
        &self.archive_sha256_tree_hash
    }
    /// <p>The retrieved byte range for archive retrieval jobs in the form <i>StartByteValue</i>-<i>EndByteValue</i>. If no range was specified in the archive retrieval, then the whole archive is retrieved. In this case, <i>StartByteValue</i> equals 0 and <i>EndByteValue</i> equals the size of the archive minus 1. For inventory retrieval or select jobs, this field is null.</p>
    pub fn retrieval_byte_range(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.retrieval_byte_range = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The retrieved byte range for archive retrieval jobs in the form <i>StartByteValue</i>-<i>EndByteValue</i>. If no range was specified in the archive retrieval, then the whole archive is retrieved. In this case, <i>StartByteValue</i> equals 0 and <i>EndByteValue</i> equals the size of the archive minus 1. For inventory retrieval or select jobs, this field is null.</p>
    pub fn set_retrieval_byte_range(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.retrieval_byte_range = input;
        self
    }
    /// <p>The retrieved byte range for archive retrieval jobs in the form <i>StartByteValue</i>-<i>EndByteValue</i>. If no range was specified in the archive retrieval, then the whole archive is retrieved. In this case, <i>StartByteValue</i> equals 0 and <i>EndByteValue</i> equals the size of the archive minus 1. For inventory retrieval or select jobs, this field is null.</p>
    pub fn get_retrieval_byte_range(&self) -> &::std::option::Option<::std::string::String> {
        &self.retrieval_byte_range
    }
    /// <p>The tier to use for a select or an archive retrieval. Valid values are <code>Expedited</code>, <code>Standard</code>, or <code>Bulk</code>. <code>Standard</code> is the default.</p>
    pub fn tier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.tier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The tier to use for a select or an archive retrieval. Valid values are <code>Expedited</code>, <code>Standard</code>, or <code>Bulk</code>. <code>Standard</code> is the default.</p>
    pub fn set_tier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.tier = input;
        self
    }
    /// <p>The tier to use for a select or an archive retrieval. Valid values are <code>Expedited</code>, <code>Standard</code>, or <code>Bulk</code>. <code>Standard</code> is the default.</p>
    pub fn get_tier(&self) -> &::std::option::Option<::std::string::String> {
        &self.tier
    }
    /// <p>Parameters used for range inventory retrieval.</p>
    pub fn inventory_retrieval_parameters(mut self, input: crate::types::InventoryRetrievalJobDescription) -> Self {
        self.inventory_retrieval_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Parameters used for range inventory retrieval.</p>
    pub fn set_inventory_retrieval_parameters(mut self, input: ::std::option::Option<crate::types::InventoryRetrievalJobDescription>) -> Self {
        self.inventory_retrieval_parameters = input;
        self
    }
    /// <p>Parameters used for range inventory retrieval.</p>
    pub fn get_inventory_retrieval_parameters(&self) -> &::std::option::Option<crate::types::InventoryRetrievalJobDescription> {
        &self.inventory_retrieval_parameters
    }
    /// <p>Contains the job output location.</p>
    pub fn job_output_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_output_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Contains the job output location.</p>
    pub fn set_job_output_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_output_path = input;
        self
    }
    /// <p>Contains the job output location.</p>
    pub fn get_job_output_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_output_path
    }
    /// <p>Contains the parameters used for a select.</p>
    pub fn select_parameters(mut self, input: crate::types::SelectParameters) -> Self {
        self.select_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the parameters used for a select.</p>
    pub fn set_select_parameters(mut self, input: ::std::option::Option<crate::types::SelectParameters>) -> Self {
        self.select_parameters = input;
        self
    }
    /// <p>Contains the parameters used for a select.</p>
    pub fn get_select_parameters(&self) -> &::std::option::Option<crate::types::SelectParameters> {
        &self.select_parameters
    }
    /// <p>Contains the location where the data from the select job is stored.</p>
    pub fn output_location(mut self, input: crate::types::OutputLocation) -> Self {
        self.output_location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the location where the data from the select job is stored.</p>
    pub fn set_output_location(mut self, input: ::std::option::Option<crate::types::OutputLocation>) -> Self {
        self.output_location = input;
        self
    }
    /// <p>Contains the location where the data from the select job is stored.</p>
    pub fn get_output_location(&self) -> &::std::option::Option<crate::types::OutputLocation> {
        &self.output_location
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeJobOutput`](crate::operation::describe_job::DescribeJobOutput).
    pub fn build(self) -> crate::operation::describe_job::DescribeJobOutput {
        crate::operation::describe_job::DescribeJobOutput {
            job_id: self.job_id,
            job_description: self.job_description,
            action: self.action,
            archive_id: self.archive_id,
            vault_arn: self.vault_arn,
            creation_date: self.creation_date,
            completed: self.completed.unwrap_or_default(),
            status_code: self.status_code,
            status_message: self.status_message,
            archive_size_in_bytes: self.archive_size_in_bytes,
            inventory_size_in_bytes: self.inventory_size_in_bytes,
            sns_topic: self.sns_topic,
            completion_date: self.completion_date,
            sha256_tree_hash: self.sha256_tree_hash,
            archive_sha256_tree_hash: self.archive_sha256_tree_hash,
            retrieval_byte_range: self.retrieval_byte_range,
            tier: self.tier,
            inventory_retrieval_parameters: self.inventory_retrieval_parameters,
            job_output_path: self.job_output_path,
            select_parameters: self.select_parameters,
            output_location: self.output_location,
            _request_id: self._request_id,
        }
    }
}
