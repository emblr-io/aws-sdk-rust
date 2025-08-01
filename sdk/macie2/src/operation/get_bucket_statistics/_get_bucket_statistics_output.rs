// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBucketStatisticsOutput {
    /// <p>The total number of buckets.</p>
    pub bucket_count: ::std::option::Option<i64>,
    /// <p>The total number of buckets that are publicly accessible due to a combination of permissions settings for each bucket.</p>
    pub bucket_count_by_effective_permission: ::std::option::Option<crate::types::BucketCountByEffectivePermission>,
    /// <p>The total number of buckets whose settings do or don't specify default server-side encryption behavior for objects that are added to the buckets.</p>
    pub bucket_count_by_encryption_type: ::std::option::Option<crate::types::BucketCountByEncryptionType>,
    /// <p>The total number of buckets whose bucket policies do or don't require server-side encryption of objects when objects are added to the buckets.</p>
    pub bucket_count_by_object_encryption_requirement: ::std::option::Option<crate::types::BucketCountPolicyAllowsUnencryptedObjectUploads>,
    /// <p>The total number of buckets that are or aren't shared with other Amazon Web Services accounts, Amazon CloudFront origin access identities (OAIs), or CloudFront origin access controls (OACs).</p>
    pub bucket_count_by_shared_access_type: ::std::option::Option<crate::types::BucketCountBySharedAccessType>,
    /// <p>The aggregated sensitive data discovery statistics for the buckets. If automated sensitive data discovery is currently disabled for your account, the value for most statistics is 0.</p>
    pub bucket_statistics_by_sensitivity: ::std::option::Option<crate::types::BucketStatisticsBySensitivity>,
    /// <p>The total number of objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub classifiable_object_count: ::std::option::Option<i64>,
    /// <p>The total storage size, in bytes, of all the objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of all applicable objects in the buckets.</p>
    pub classifiable_size_in_bytes: ::std::option::Option<i64>,
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently retrieved bucket or object metadata from Amazon S3 for the buckets.</p>
    pub last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The total number of objects in the buckets.</p>
    pub object_count: ::std::option::Option<i64>,
    /// <p>The total storage size, in bytes, of the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each object in the buckets. This value doesn't reflect the storage size of all versions of the objects in the buckets.</p>
    pub size_in_bytes: ::std::option::Option<i64>,
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of the applicable objects in the buckets.</p>
    pub size_in_bytes_compressed: ::std::option::Option<i64>,
    /// <p>The total number of objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub unclassifiable_object_count: ::std::option::Option<crate::types::ObjectLevelStatistics>,
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub unclassifiable_object_size_in_bytes: ::std::option::Option<crate::types::ObjectLevelStatistics>,
    _request_id: Option<String>,
}
impl GetBucketStatisticsOutput {
    /// <p>The total number of buckets.</p>
    pub fn bucket_count(&self) -> ::std::option::Option<i64> {
        self.bucket_count
    }
    /// <p>The total number of buckets that are publicly accessible due to a combination of permissions settings for each bucket.</p>
    pub fn bucket_count_by_effective_permission(&self) -> ::std::option::Option<&crate::types::BucketCountByEffectivePermission> {
        self.bucket_count_by_effective_permission.as_ref()
    }
    /// <p>The total number of buckets whose settings do or don't specify default server-side encryption behavior for objects that are added to the buckets.</p>
    pub fn bucket_count_by_encryption_type(&self) -> ::std::option::Option<&crate::types::BucketCountByEncryptionType> {
        self.bucket_count_by_encryption_type.as_ref()
    }
    /// <p>The total number of buckets whose bucket policies do or don't require server-side encryption of objects when objects are added to the buckets.</p>
    pub fn bucket_count_by_object_encryption_requirement(
        &self,
    ) -> ::std::option::Option<&crate::types::BucketCountPolicyAllowsUnencryptedObjectUploads> {
        self.bucket_count_by_object_encryption_requirement.as_ref()
    }
    /// <p>The total number of buckets that are or aren't shared with other Amazon Web Services accounts, Amazon CloudFront origin access identities (OAIs), or CloudFront origin access controls (OACs).</p>
    pub fn bucket_count_by_shared_access_type(&self) -> ::std::option::Option<&crate::types::BucketCountBySharedAccessType> {
        self.bucket_count_by_shared_access_type.as_ref()
    }
    /// <p>The aggregated sensitive data discovery statistics for the buckets. If automated sensitive data discovery is currently disabled for your account, the value for most statistics is 0.</p>
    pub fn bucket_statistics_by_sensitivity(&self) -> ::std::option::Option<&crate::types::BucketStatisticsBySensitivity> {
        self.bucket_statistics_by_sensitivity.as_ref()
    }
    /// <p>The total number of objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub fn classifiable_object_count(&self) -> ::std::option::Option<i64> {
        self.classifiable_object_count
    }
    /// <p>The total storage size, in bytes, of all the objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of all applicable objects in the buckets.</p>
    pub fn classifiable_size_in_bytes(&self) -> ::std::option::Option<i64> {
        self.classifiable_size_in_bytes
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently retrieved bucket or object metadata from Amazon S3 for the buckets.</p>
    pub fn last_updated(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated.as_ref()
    }
    /// <p>The total number of objects in the buckets.</p>
    pub fn object_count(&self) -> ::std::option::Option<i64> {
        self.object_count
    }
    /// <p>The total storage size, in bytes, of the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each object in the buckets. This value doesn't reflect the storage size of all versions of the objects in the buckets.</p>
    pub fn size_in_bytes(&self) -> ::std::option::Option<i64> {
        self.size_in_bytes
    }
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of the applicable objects in the buckets.</p>
    pub fn size_in_bytes_compressed(&self) -> ::std::option::Option<i64> {
        self.size_in_bytes_compressed
    }
    /// <p>The total number of objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn unclassifiable_object_count(&self) -> ::std::option::Option<&crate::types::ObjectLevelStatistics> {
        self.unclassifiable_object_count.as_ref()
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn unclassifiable_object_size_in_bytes(&self) -> ::std::option::Option<&crate::types::ObjectLevelStatistics> {
        self.unclassifiable_object_size_in_bytes.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetBucketStatisticsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetBucketStatisticsOutput {
    /// Creates a new builder-style object to manufacture [`GetBucketStatisticsOutput`](crate::operation::get_bucket_statistics::GetBucketStatisticsOutput).
    pub fn builder() -> crate::operation::get_bucket_statistics::builders::GetBucketStatisticsOutputBuilder {
        crate::operation::get_bucket_statistics::builders::GetBucketStatisticsOutputBuilder::default()
    }
}

/// A builder for [`GetBucketStatisticsOutput`](crate::operation::get_bucket_statistics::GetBucketStatisticsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBucketStatisticsOutputBuilder {
    pub(crate) bucket_count: ::std::option::Option<i64>,
    pub(crate) bucket_count_by_effective_permission: ::std::option::Option<crate::types::BucketCountByEffectivePermission>,
    pub(crate) bucket_count_by_encryption_type: ::std::option::Option<crate::types::BucketCountByEncryptionType>,
    pub(crate) bucket_count_by_object_encryption_requirement: ::std::option::Option<crate::types::BucketCountPolicyAllowsUnencryptedObjectUploads>,
    pub(crate) bucket_count_by_shared_access_type: ::std::option::Option<crate::types::BucketCountBySharedAccessType>,
    pub(crate) bucket_statistics_by_sensitivity: ::std::option::Option<crate::types::BucketStatisticsBySensitivity>,
    pub(crate) classifiable_object_count: ::std::option::Option<i64>,
    pub(crate) classifiable_size_in_bytes: ::std::option::Option<i64>,
    pub(crate) last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) object_count: ::std::option::Option<i64>,
    pub(crate) size_in_bytes: ::std::option::Option<i64>,
    pub(crate) size_in_bytes_compressed: ::std::option::Option<i64>,
    pub(crate) unclassifiable_object_count: ::std::option::Option<crate::types::ObjectLevelStatistics>,
    pub(crate) unclassifiable_object_size_in_bytes: ::std::option::Option<crate::types::ObjectLevelStatistics>,
    _request_id: Option<String>,
}
impl GetBucketStatisticsOutputBuilder {
    /// <p>The total number of buckets.</p>
    pub fn bucket_count(mut self, input: i64) -> Self {
        self.bucket_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of buckets.</p>
    pub fn set_bucket_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.bucket_count = input;
        self
    }
    /// <p>The total number of buckets.</p>
    pub fn get_bucket_count(&self) -> &::std::option::Option<i64> {
        &self.bucket_count
    }
    /// <p>The total number of buckets that are publicly accessible due to a combination of permissions settings for each bucket.</p>
    pub fn bucket_count_by_effective_permission(mut self, input: crate::types::BucketCountByEffectivePermission) -> Self {
        self.bucket_count_by_effective_permission = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of buckets that are publicly accessible due to a combination of permissions settings for each bucket.</p>
    pub fn set_bucket_count_by_effective_permission(mut self, input: ::std::option::Option<crate::types::BucketCountByEffectivePermission>) -> Self {
        self.bucket_count_by_effective_permission = input;
        self
    }
    /// <p>The total number of buckets that are publicly accessible due to a combination of permissions settings for each bucket.</p>
    pub fn get_bucket_count_by_effective_permission(&self) -> &::std::option::Option<crate::types::BucketCountByEffectivePermission> {
        &self.bucket_count_by_effective_permission
    }
    /// <p>The total number of buckets whose settings do or don't specify default server-side encryption behavior for objects that are added to the buckets.</p>
    pub fn bucket_count_by_encryption_type(mut self, input: crate::types::BucketCountByEncryptionType) -> Self {
        self.bucket_count_by_encryption_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of buckets whose settings do or don't specify default server-side encryption behavior for objects that are added to the buckets.</p>
    pub fn set_bucket_count_by_encryption_type(mut self, input: ::std::option::Option<crate::types::BucketCountByEncryptionType>) -> Self {
        self.bucket_count_by_encryption_type = input;
        self
    }
    /// <p>The total number of buckets whose settings do or don't specify default server-side encryption behavior for objects that are added to the buckets.</p>
    pub fn get_bucket_count_by_encryption_type(&self) -> &::std::option::Option<crate::types::BucketCountByEncryptionType> {
        &self.bucket_count_by_encryption_type
    }
    /// <p>The total number of buckets whose bucket policies do or don't require server-side encryption of objects when objects are added to the buckets.</p>
    pub fn bucket_count_by_object_encryption_requirement(mut self, input: crate::types::BucketCountPolicyAllowsUnencryptedObjectUploads) -> Self {
        self.bucket_count_by_object_encryption_requirement = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of buckets whose bucket policies do or don't require server-side encryption of objects when objects are added to the buckets.</p>
    pub fn set_bucket_count_by_object_encryption_requirement(
        mut self,
        input: ::std::option::Option<crate::types::BucketCountPolicyAllowsUnencryptedObjectUploads>,
    ) -> Self {
        self.bucket_count_by_object_encryption_requirement = input;
        self
    }
    /// <p>The total number of buckets whose bucket policies do or don't require server-side encryption of objects when objects are added to the buckets.</p>
    pub fn get_bucket_count_by_object_encryption_requirement(
        &self,
    ) -> &::std::option::Option<crate::types::BucketCountPolicyAllowsUnencryptedObjectUploads> {
        &self.bucket_count_by_object_encryption_requirement
    }
    /// <p>The total number of buckets that are or aren't shared with other Amazon Web Services accounts, Amazon CloudFront origin access identities (OAIs), or CloudFront origin access controls (OACs).</p>
    pub fn bucket_count_by_shared_access_type(mut self, input: crate::types::BucketCountBySharedAccessType) -> Self {
        self.bucket_count_by_shared_access_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of buckets that are or aren't shared with other Amazon Web Services accounts, Amazon CloudFront origin access identities (OAIs), or CloudFront origin access controls (OACs).</p>
    pub fn set_bucket_count_by_shared_access_type(mut self, input: ::std::option::Option<crate::types::BucketCountBySharedAccessType>) -> Self {
        self.bucket_count_by_shared_access_type = input;
        self
    }
    /// <p>The total number of buckets that are or aren't shared with other Amazon Web Services accounts, Amazon CloudFront origin access identities (OAIs), or CloudFront origin access controls (OACs).</p>
    pub fn get_bucket_count_by_shared_access_type(&self) -> &::std::option::Option<crate::types::BucketCountBySharedAccessType> {
        &self.bucket_count_by_shared_access_type
    }
    /// <p>The aggregated sensitive data discovery statistics for the buckets. If automated sensitive data discovery is currently disabled for your account, the value for most statistics is 0.</p>
    pub fn bucket_statistics_by_sensitivity(mut self, input: crate::types::BucketStatisticsBySensitivity) -> Self {
        self.bucket_statistics_by_sensitivity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The aggregated sensitive data discovery statistics for the buckets. If automated sensitive data discovery is currently disabled for your account, the value for most statistics is 0.</p>
    pub fn set_bucket_statistics_by_sensitivity(mut self, input: ::std::option::Option<crate::types::BucketStatisticsBySensitivity>) -> Self {
        self.bucket_statistics_by_sensitivity = input;
        self
    }
    /// <p>The aggregated sensitive data discovery statistics for the buckets. If automated sensitive data discovery is currently disabled for your account, the value for most statistics is 0.</p>
    pub fn get_bucket_statistics_by_sensitivity(&self) -> &::std::option::Option<crate::types::BucketStatisticsBySensitivity> {
        &self.bucket_statistics_by_sensitivity
    }
    /// <p>The total number of objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub fn classifiable_object_count(mut self, input: i64) -> Self {
        self.classifiable_object_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub fn set_classifiable_object_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.classifiable_object_count = input;
        self
    }
    /// <p>The total number of objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    pub fn get_classifiable_object_count(&self) -> &::std::option::Option<i64> {
        &self.classifiable_object_count
    }
    /// <p>The total storage size, in bytes, of all the objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of all applicable objects in the buckets.</p>
    pub fn classifiable_size_in_bytes(mut self, input: i64) -> Self {
        self.classifiable_size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total storage size, in bytes, of all the objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of all applicable objects in the buckets.</p>
    pub fn set_classifiable_size_in_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.classifiable_size_in_bytes = input;
        self
    }
    /// <p>The total storage size, in bytes, of all the objects that Amazon Macie can analyze in the buckets. These objects use a supported storage class and have a file name extension for a supported file or storage format.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of all applicable objects in the buckets.</p>
    pub fn get_classifiable_size_in_bytes(&self) -> &::std::option::Option<i64> {
        &self.classifiable_size_in_bytes
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently retrieved bucket or object metadata from Amazon S3 for the buckets.</p>
    pub fn last_updated(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently retrieved bucket or object metadata from Amazon S3 for the buckets.</p>
    pub fn set_last_updated(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated = input;
        self
    }
    /// <p>The date and time, in UTC and extended ISO 8601 format, when Amazon Macie most recently retrieved bucket or object metadata from Amazon S3 for the buckets.</p>
    pub fn get_last_updated(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated
    }
    /// <p>The total number of objects in the buckets.</p>
    pub fn object_count(mut self, input: i64) -> Self {
        self.object_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of objects in the buckets.</p>
    pub fn set_object_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.object_count = input;
        self
    }
    /// <p>The total number of objects in the buckets.</p>
    pub fn get_object_count(&self) -> &::std::option::Option<i64> {
        &self.object_count
    }
    /// <p>The total storage size, in bytes, of the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each object in the buckets. This value doesn't reflect the storage size of all versions of the objects in the buckets.</p>
    pub fn size_in_bytes(mut self, input: i64) -> Self {
        self.size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total storage size, in bytes, of the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each object in the buckets. This value doesn't reflect the storage size of all versions of the objects in the buckets.</p>
    pub fn set_size_in_bytes(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size_in_bytes = input;
        self
    }
    /// <p>The total storage size, in bytes, of the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each object in the buckets. This value doesn't reflect the storage size of all versions of the objects in the buckets.</p>
    pub fn get_size_in_bytes(&self) -> &::std::option::Option<i64> {
        &self.size_in_bytes
    }
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of the applicable objects in the buckets.</p>
    pub fn size_in_bytes_compressed(mut self, input: i64) -> Self {
        self.size_in_bytes_compressed = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of the applicable objects in the buckets.</p>
    pub fn set_size_in_bytes_compressed(mut self, input: ::std::option::Option<i64>) -> Self {
        self.size_in_bytes_compressed = input;
        self
    }
    /// <p>The total storage size, in bytes, of the objects that are compressed (.gz, .gzip, .zip) files in the buckets.</p>
    /// <p>If versioning is enabled for any of the buckets, this value is based on the size of the latest version of each applicable object in the buckets. This value doesn't reflect the storage size of all versions of the applicable objects in the buckets.</p>
    pub fn get_size_in_bytes_compressed(&self) -> &::std::option::Option<i64> {
        &self.size_in_bytes_compressed
    }
    /// <p>The total number of objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn unclassifiable_object_count(mut self, input: crate::types::ObjectLevelStatistics) -> Self {
        self.unclassifiable_object_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn set_unclassifiable_object_count(mut self, input: ::std::option::Option<crate::types::ObjectLevelStatistics>) -> Self {
        self.unclassifiable_object_count = input;
        self
    }
    /// <p>The total number of objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn get_unclassifiable_object_count(&self) -> &::std::option::Option<crate::types::ObjectLevelStatistics> {
        &self.unclassifiable_object_count
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn unclassifiable_object_size_in_bytes(mut self, input: crate::types::ObjectLevelStatistics) -> Self {
        self.unclassifiable_object_size_in_bytes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn set_unclassifiable_object_size_in_bytes(mut self, input: ::std::option::Option<crate::types::ObjectLevelStatistics>) -> Self {
        self.unclassifiable_object_size_in_bytes = input;
        self
    }
    /// <p>The total storage size, in bytes, of the objects that Amazon Macie can't analyze in the buckets. These objects don't use a supported storage class or don't have a file name extension for a supported file or storage format.</p>
    pub fn get_unclassifiable_object_size_in_bytes(&self) -> &::std::option::Option<crate::types::ObjectLevelStatistics> {
        &self.unclassifiable_object_size_in_bytes
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetBucketStatisticsOutput`](crate::operation::get_bucket_statistics::GetBucketStatisticsOutput).
    pub fn build(self) -> crate::operation::get_bucket_statistics::GetBucketStatisticsOutput {
        crate::operation::get_bucket_statistics::GetBucketStatisticsOutput {
            bucket_count: self.bucket_count,
            bucket_count_by_effective_permission: self.bucket_count_by_effective_permission,
            bucket_count_by_encryption_type: self.bucket_count_by_encryption_type,
            bucket_count_by_object_encryption_requirement: self.bucket_count_by_object_encryption_requirement,
            bucket_count_by_shared_access_type: self.bucket_count_by_shared_access_type,
            bucket_statistics_by_sensitivity: self.bucket_statistics_by_sensitivity,
            classifiable_object_count: self.classifiable_object_count,
            classifiable_size_in_bytes: self.classifiable_size_in_bytes,
            last_updated: self.last_updated,
            object_count: self.object_count,
            size_in_bytes: self.size_in_bytes,
            size_in_bytes_compressed: self.size_in_bytes_compressed,
            unclassifiable_object_count: self.unclassifiable_object_count,
            unclassifiable_object_size_in_bytes: self.unclassifiable_object_size_in_bytes,
            _request_id: self._request_id,
        }
    }
}
