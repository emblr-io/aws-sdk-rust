// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Provides statistical data and other information about an S3 bucket that Amazon Macie monitors and analyzes for your account. By default, object count and storage size values include data for object parts that are the result of incomplete multipart uploads. For more information, see <a href="https://docs.aws.amazon.com/macie/latest/user/monitoring-s3-how-it-works.html">How Macie monitors Amazon S3 data security</a> in the <i>Amazon Macie User Guide</i>.</p>
/// <p>If an error or issue prevents Macie from retrieving and processing information about the bucket or the bucket's objects, the value for many of these properties is null. Key exceptions are accountId and bucketName. To identify the cause, refer to the errorCode and errorMessage values.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MatchingBucket {
    /// <p>The unique identifier for the Amazon Web Services account that owns the bucket.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether automated sensitive data discovery is currently configured to analyze objects in the bucket. Possible values are: MONITORED, the bucket is included in analyses; and, NOT_MONITORED, the bucket is excluded from analyses. If automated sensitive data discovery is disabled for your account, this value is NOT_MONITORED.</p>
    pub automated_discovery_monitoring_status: ::std::option::Option<crate::types::AutomatedDiscoveryMonitoringStatus>,
    /// <p>The name of the bucket.</p>
    pub bucket_name: ::std::option::Option<::std::string::String>,
    /// <p>The total number of objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub classifiable_object_count: ::std::option::Option<i64>,
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for the bucket, Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub classifiable_size_in_bytes: ::std::option::Option<i64>,
    /// <p>The code for an error or issue that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCESS_DENIED - Macie doesn't have permission to retrieve the information. For example, the bucket has a restrictive bucket policy and Amazon S3 denied the request.</p></li>
    /// <li>
    /// <p>BUCKET_COUNT_EXCEEDS_QUOTA - Retrieving and processing the information would exceed the quota for the number of buckets that Macie monitors for an account (10,000).</p></li>
    /// </ul>
    /// <p>If this value is null, Macie was able to retrieve and process the information.</p>
    pub error_code: ::std::option::Option<crate::types::BucketMetadataErrorCode>,
    /// <p>A brief description of the error or issue (errorCode) that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. This value is null if Macie was able to retrieve and process the information.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether any one-time or recurring classification jobs are configured to analyze objects in the bucket, and, if so, the details of the job that ran most recently.</p>
    pub job_details: ::std::option::Option<crate::types::JobDetails>,
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently analyzed objects in the bucket while performing automated sensitive data discovery. This value is null if this analysis hasn't occurred.</p>
    pub last_automated_discovery_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The total number of objects in the bucket.</p>
    pub object_count: ::std::option::Option<i64>,
    /// <p>The total number of objects in the bucket, grouped by server-side encryption type. This includes a grouping that reports the total number of objects that aren't encrypted or use client-side encryption.</p>
    pub object_count_by_encryption_type: ::std::option::Option<crate::types::ObjectCountByEncryptionType>,
    /// <p>The sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive).</p>
    /// <p>If automated sensitive data discovery has never been enabled for your account or it's been disabled for your organization or standalone account for more than 30 days, possible values are: 1, the bucket is empty; or, 50, the bucket stores objects but it's been excluded from recent analyses.</p>
    pub sensitivity_score: ::std::option::Option<i32>,
    /// <p>The total storage size, in bytes, of the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each object in the bucket. This value doesn't reflect the storage size of all versions of each object in the bucket.</p>
    pub size_in_bytes: ::std::option::Option<i64>,
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub size_in_bytes_compressed: ::std::option::Option<i64>,
    /// <p>The total number of objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub unclassifiable_object_count: ::std::option::Option<crate::types::ObjectLevelStatistics>,
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub unclassifiable_object_size_in_bytes: ::std::option::Option<crate::types::ObjectLevelStatistics>,
}
impl MatchingBucket {
    /// <p>The unique identifier for the Amazon Web Services account that owns the bucket.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>Specifies whether automated sensitive data discovery is currently configured to analyze objects in the bucket. Possible values are: MONITORED, the bucket is included in analyses; and, NOT_MONITORED, the bucket is excluded from analyses. If automated sensitive data discovery is disabled for your account, this value is NOT_MONITORED.</p>
    pub fn automated_discovery_monitoring_status(&self) -> ::std::option::Option<&crate::types::AutomatedDiscoveryMonitoringStatus> {
        self.automated_discovery_monitoring_status.as_ref()
    }
    /// <p>The name of the bucket.</p>
    pub fn bucket_name(&self) -> ::std::option::Option<&str> {
        self.bucket_name.as_deref()
    }
    /// <p>The total number of objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub fn classifiable_object_count(&self) -> ::std::option::Option<i64> {
        self.classifiable_object_count
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for the bucket, Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub fn classifiable_size_in_bytes(&self) -> ::std::option::Option<i64> {
        self.classifiable_size_in_bytes
    }
    /// <p>The code for an error or issue that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCESS_DENIED - Macie doesn't have permission to retrieve the information. For example, the bucket has a restrictive bucket policy and Amazon S3 denied the request.</p></li>
    /// <li>
    /// <p>BUCKET_COUNT_EXCEEDS_QUOTA - Retrieving and processing the information would exceed the quota for the number of buckets that Macie monitors for an account (10,000).</p></li>
    /// </ul>
    /// <p>If this value is null, Macie was able to retrieve and process the information.</p>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::BucketMetadataErrorCode> {
        self.error_code.as_ref()
    }
    /// <p>A brief description of the error or issue (errorCode) that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. This value is null if Macie was able to retrieve and process the information.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>Specifies whether any one-time or recurring classification jobs are configured to analyze objects in the bucket, and, if so, the details of the job that ran most recently.</p>
    pub fn job_details(&self) -> ::std::option::Option<&crate::types::JobDetails> {
        self.job_details.as_ref()
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently analyzed objects in the bucket while performing automated sensitive data discovery. This value is null if this analysis hasn't occurred.</p>
    pub fn last_automated_discovery_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_automated_discovery_time.as_ref()
    }
    /// <p>The total number of objects in the bucket.</p>
    pub fn object_count(&self) -> ::std::option::Option<i64> {
        self.object_count
    }
    /// <p>The total number of objects in the bucket, grouped by server-side encryption type. This includes a grouping that reports the total number of objects that aren't encrypted or use client-side encryption.</p>
    pub fn object_count_by_encryption_type(&self) -> ::std::option::Option<&crate::types::ObjectCountByEncryptionType> {
        self.object_count_by_encryption_type.as_ref()
    }
    /// <p>The sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive).</p>
    /// <p>If automated sensitive data discovery has never been enabled for your account or it's been disabled for your organization or standalone account for more than 30 days, possible values are: 1, the bucket is empty; or, 50, the bucket stores objects but it's been excluded from recent analyses.</p>
    pub fn sensitivity_score(&self) -> ::std::option::Option<i32> {
        self.sensitivity_score
    }
    /// <p>The total storage size, in bytes, of the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each object in the bucket. This value doesn't reflect the storage size of all versions of each object in the bucket.</p>
    pub fn size_in_bytes(&self) -> ::std::option::Option<i64> {
        self.size_in_bytes
    }
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub fn size_in_bytes_compressed(&self) -> ::std::option::Option<i64> {
        self.size_in_bytes_compressed
    }
    /// <p>The total number of objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn unclassifiable_object_count(&self) -> ::std::option::Option<&crate::types::ObjectLevelStatistics> {
        self.unclassifiable_object_count.as_ref()
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn unclassifiable_object_size_in_bytes(&self) -> ::std::option::Option<&crate::types::ObjectLevelStatistics> {
        self.unclassifiable_object_size_in_bytes.as_ref()
    }
}
impl MatchingBucket {
    /// Creates a new builder-style object to manufacture [`MatchingBucket`](crate::types::MatchingBucket).
    pub fn builder() -> crate::types::builders::MatchingBucketBuilder {
        crate::types::builders::MatchingBucketBuilder::default()
    }
}

/// A builder for [`MatchingBucket`](crate::types::MatchingBucket).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MatchingBucketBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) automated_discovery_monitoring_status: ::std::option::Option<crate::types::AutomatedDiscoveryMonitoringStatus>,
    pub(crate) bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) classifiable_object_count: ::std::option::Option<i64>,
    pub(crate) classifiable_size_in_bytes: ::std::option::Option<i64>,
    pub(crate) error_code: ::std::option::Option<crate::types::BucketMetadataErrorCode>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) job_details: ::std::option::Option<crate::types::JobDetails>,
    pub(crate) last_automated_discovery_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) object_count: ::std::option::Option<i64>,
    pub(crate) object_count_by_encryption_type: ::std::option::Option<crate::types::ObjectCountByEncryptionType>,
    pub(crate) sensitivity_score: ::std::option::Option<i32>,
    pub(crate) size_in_bytes: ::std::option::Option<i64>,
    pub(crate) size_in_bytes_compressed: ::std::option::Option<i64>,
    pub(crate) unclassifiable_object_count: ::std::option::Option<crate::types::ObjectLevelStatistics>,
    pub(crate) unclassifiable_object_size_in_bytes: ::std::option::Option<crate::types::ObjectLevelStatistics>,
}
impl MatchingBucketBuilder {
    /// <p>The unique identifier for the Amazon Web Services account that owns the bucket.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the Amazon Web Services account that owns the bucket.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The unique identifier for the Amazon Web Services account that owns the bucket.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>Specifies whether automated sensitive data discovery is currently configured to analyze objects in the bucket. Possible values are: MONITORED, the bucket is included in analyses; and, NOT_MONITORED, the bucket is excluded from analyses. If automated sensitive data discovery is disabled for your account, this value is NOT_MONITORED.</p>
    pub fn automated_discovery_monitoring_status(mut self, input: crate::types::AutomatedDiscoveryMonitoringStatus) -> Self {
        self.automated_discovery_monitoring_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether automated sensitive data discovery is currently configured to analyze objects in the bucket. Possible values are: MONITORED, the bucket is included in analyses; and, NOT_MONITORED, the bucket is excluded from analyses. If automated sensitive data discovery is disabled for your account, this value is NOT_MONITORED.</p>
    pub fn set_automated_discovery_monitoring_status(
        mut self,
        input: ::std::option::Option<crate::types::AutomatedDiscoveryMonitoringStatus>,
    ) -> Self {
        self.automated_discovery_monitoring_status = input;
        self
    }
    /// <p>Specifies whether automated sensitive data discovery is currently configured to analyze objects in the bucket. Possible values are: MONITORED, the bucket is included in analyses; and, NOT_MONITORED, the bucket is excluded from analyses. If automated sensitive data discovery is disabled for your account, this value is NOT_MONITORED.</p>
    pub fn get_automated_discovery_monitoring_status(&self) -> &::std::option::Option<crate::types::AutomatedDiscoveryMonitoringStatus> {
        &self.automated_discovery_monitoring_status
    }
    /// <p>The name of the bucket.</p>
    pub fn bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bucket.</p>
    pub fn set_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_name = input;
        self
    }
    /// <p>The name of the bucket.</p>
    pub fn get_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_name
    }
    /// <p>The total number of objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub fn classifiable_object_count(mut self, input: i64) -> Self {
        self.classifiable_object_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub fn set_classifiable_object_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.classifiable_object_count = input;
        self
    }
    /// <p>The total number of objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub fn get_classifiable_object_count(&self) -> &::std::option::Option<i64> {
        &self.classifiable_object_count
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for the bucket, Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub fn classifiable_size_in_bytes(mut self, input: i64) -> Self {
        self.classifiable_size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for the bucket, Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub fn set_classifiable_size_in_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.classifiable_size_in_bytes = input;
        self
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can analyze in the bucket. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for the bucket, Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub fn get_classifiable_size_in_bytes(&self) -> &::std::option::Option<i64> {
        &self.classifiable_size_in_bytes
    }
    /// <p>The code for an error or issue that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCESS_DENIED - Macie doesn't have permission to retrieve the information. For example, the bucket has a restrictive bucket policy and Amazon S3 denied the request.</p></li>
    /// <li>
    /// <p>BUCKET_COUNT_EXCEEDS_QUOTA - Retrieving and processing the information would exceed the quota for the number of buckets that Macie monitors for an account (10,000).</p></li>
    /// </ul>
    /// <p>If this value is null, Macie was able to retrieve and process the information.</p>
    pub fn error_code(mut self, input: crate::types::BucketMetadataErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The code for an error or issue that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCESS_DENIED - Macie doesn't have permission to retrieve the information. For example, the bucket has a restrictive bucket policy and Amazon S3 denied the request.</p></li>
    /// <li>
    /// <p>BUCKET_COUNT_EXCEEDS_QUOTA - Retrieving and processing the information would exceed the quota for the number of buckets that Macie monitors for an account (10,000).</p></li>
    /// </ul>
    /// <p>If this value is null, Macie was able to retrieve and process the information.</p>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::BucketMetadataErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>The code for an error or issue that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. Possible values are:</p>
    /// <ul>
    /// <li>
    /// <p>ACCESS_DENIED - Macie doesn't have permission to retrieve the information. For example, the bucket has a restrictive bucket policy and Amazon S3 denied the request.</p></li>
    /// <li>
    /// <p>BUCKET_COUNT_EXCEEDS_QUOTA - Retrieving and processing the information would exceed the quota for the number of buckets that Macie monitors for an account (10,000).</p></li>
    /// </ul>
    /// <p>If this value is null, Macie was able to retrieve and process the information.</p>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::BucketMetadataErrorCode> {
        &self.error_code
    }
    /// <p>A brief description of the error or issue (errorCode) that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. This value is null if Macie was able to retrieve and process the information.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A brief description of the error or issue (errorCode) that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. This value is null if Macie was able to retrieve and process the information.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>A brief description of the error or issue (errorCode) that prevented Amazon Macie from retrieving and processing information about the bucket and the bucket's objects. This value is null if Macie was able to retrieve and process the information.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// <p>Specifies whether any one-time or recurring classification jobs are configured to analyze objects in the bucket, and, if so, the details of the job that ran most recently.</p>
    pub fn job_details(mut self, input: crate::types::JobDetails) -> Self {
        self.job_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether any one-time or recurring classification jobs are configured to analyze objects in the bucket, and, if so, the details of the job that ran most recently.</p>
    pub fn set_job_details(mut self, input: ::std::option::Option<crate::types::JobDetails>) -> Self {
        self.job_details = input;
        self
    }
    /// <p>Specifies whether any one-time or recurring classification jobs are configured to analyze objects in the bucket, and, if so, the details of the job that ran most recently.</p>
    pub fn get_job_details(&self) -> &::std::option::Option<crate::types::JobDetails> {
        &self.job_details
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently analyzed objects in the bucket while performing automated sensitive data discovery. This value is null if this analysis hasn't occurred.</p>
    pub fn last_automated_discovery_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_automated_discovery_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently analyzed objects in the bucket while performing automated sensitive data discovery. This value is null if this analysis hasn't occurred.</p>
    pub fn set_last_automated_discovery_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_automated_discovery_time = input;
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently analyzed objects in the bucket while performing automated sensitive data discovery. This value is null if this analysis hasn't occurred.</p>
    pub fn get_last_automated_discovery_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_automated_discovery_time
    }
    /// <p>The total number of objects in the bucket.</p>
    pub fn object_count(mut self, input: i64) -> Self {
        self.object_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of objects in the bucket.</p>
    pub fn set_object_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.object_count = input;
        self
    }
    /// <p>The total number of objects in the bucket.</p>
    pub fn get_object_count(&self) -> &::std::option::Option<i64> {
        &self.object_count
    }
    /// <p>The total number of objects in the bucket, grouped by server-side encryption type. This includes a grouping that reports the total number of objects that aren't encrypted or use client-side encryption.</p>
    pub fn object_count_by_encryption_type(mut self, input: crate::types::ObjectCountByEncryptionType) -> Self {
        self.object_count_by_encryption_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of objects in the bucket, grouped by server-side encryption type. This includes a grouping that reports the total number of objects that aren't encrypted or use client-side encryption.</p>
    pub fn set_object_count_by_encryption_type(mut self, input: ::std::option::Option<crate::types::ObjectCountByEncryptionType>) -> Self {
        self.object_count_by_encryption_type = input;
        self
    }
    /// <p>The total number of objects in the bucket, grouped by server-side encryption type. This includes a grouping that reports the total number of objects that aren't encrypted or use client-side encryption.</p>
    pub fn get_object_count_by_encryption_type(&self) -> &::std::option::Option<crate::types::ObjectCountByEncryptionType> {
        &self.object_count_by_encryption_type
    }
    /// <p>The sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive).</p>
    /// <p>If automated sensitive data discovery has never been enabled for your account or it's been disabled for your organization or standalone account for more than 30 days, possible values are: 1, the bucket is empty; or, 50, the bucket stores objects but it's been excluded from recent analyses.</p>
    pub fn sensitivity_score(mut self, input: i32) -> Self {
        self.sensitivity_score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive).</p>
    /// <p>If automated sensitive data discovery has never been enabled for your account or it's been disabled for your organization or standalone account for more than 30 days, possible values are: 1, the bucket is empty; or, 50, the bucket stores objects but it's been excluded from recent analyses.</p>
    pub fn set_sensitivity_score(mut self, input: ::std::option::Option<i32>) -> Self {
        self.sensitivity_score = input;
        self
    }
    /// <p>The sensitivity score for the bucket, ranging from -1 (classification error) to 100 (sensitive).</p>
    /// <p>If automated sensitive data discovery has never been enabled for your account or it's been disabled for your organization or standalone account for more than 30 days, possible values are: 1, the bucket is empty; or, 50, the bucket stores objects but it's been excluded from recent analyses.</p>
    pub fn get_sensitivity_score(&self) -> &::std::option::Option<i32> {
        &self.sensitivity_score
    }
    /// <p>The total storage size, in bytes, of the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each object in the bucket. This value doesn't reflect the storage size of all versions of each object in the bucket.</p>
    pub fn size_in_bytes(mut self, input: i64) -> Self {
        self.size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total storage size, in bytes, of the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each object in the bucket. This value doesn't reflect the storage size of all versions of each object in the bucket.</p>
    pub fn set_size_in_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size_in_bytes = input;
        self
    }
    /// <p>The total storage size, in bytes, of the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each object in the bucket. This value doesn't reflect the storage size of all versions of each object in the bucket.</p>
    pub fn get_size_in_bytes(&self) -> &::std::option::Option<i64> {
        &self.size_in_bytes
    }
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub fn size_in_bytes_compressed(mut self, input: i64) -> Self {
        self.size_in_bytes_compressed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub fn set_size_in_bytes_compressed(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size_in_bytes_compressed = input;
        self
    }
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the bucket.</p>
    /// <p>If versioning is enabled for the bucket, Amazon Macie calculates this value based on the size of the latest version of each applicable object in the bucket. This value doesn't reflect the storage size of all versions of each applicable object in the bucket.</p>
    pub fn get_size_in_bytes_compressed(&self) -> &::std::option::Option<i64> {
        &self.size_in_bytes_compressed
    }
    /// <p>The total number of objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn unclassifiable_object_count(mut self, input: crate::types::ObjectLevelStatistics) -> Self {
        self.unclassifiable_object_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn set_unclassifiable_object_count(mut self, input: ::std::option::Option<crate::types::ObjectLevelStatistics>) -> Self {
        self.unclassifiable_object_count = input;
        self
    }
    /// <p>The total number of objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn get_unclassifiable_object_count(&self) -> &::std::option::Option<crate::types::ObjectLevelStatistics> {
        &self.unclassifiable_object_count
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn unclassifiable_object_size_in_bytes(mut self, input: crate::types::ObjectLevelStatistics) -> Self {
        self.unclassifiable_object_size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn set_unclassifiable_object_size_in_bytes(mut self, input: ::std::option::Option<crate::types::ObjectLevelStatistics>) -> Self {
        self.unclassifiable_object_size_in_bytes = input;
        self
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the bucket. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn get_unclassifiable_object_size_in_bytes(&self) -> &::std::option::Option<crate::types::ObjectLevelStatistics> {
        &self.unclassifiable_object_size_in_bytes
    }
    /// Consumes the builder and constructs a [`MatchingBucket`](crate::types::MatchingBucket).
    pub fn build(self) -> crate::types::MatchingBucket {
        crate::types::MatchingBucket {
            account_id: self.account_id,
            automated_discovery_monitoring_status: self.automated_discovery_monitoring_status,
            bucket_name: self.bucket_name,
            classifiable_object_count: self.classifiable_object_count,
            classifiable_size_in_bytes: self.classifiable_size_in_bytes,
            error_code: self.error_code,
            error_message: self.error_message,
            job_details: self.job_details,
            last_automated_discovery_time: self.last_automated_discovery_time,
            object_count: self.object_count,
            object_count_by_encryption_type: self.object_count_by_encryption_type,
            sensitivity_score: self.sensitivity_score,
            size_in_bytes: self.size_in_bytes,
            size_in_bytes_compressed: self.size_in_bytes_compressed,
            unclassifiable_object_count: self.unclassifiable_object_count,
            unclassifiable_object_size_in_bytes: self.unclassifiable_object_size_in_bytes,
        }
    }
}
