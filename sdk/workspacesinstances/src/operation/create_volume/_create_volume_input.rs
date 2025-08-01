// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies volume creation parameters.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct CreateVolumeInput {
    /// <p>Availability zone for the volume.</p>
    pub availability_zone: ::std::option::Option<::std::string::String>,
    /// <p>Unique token to prevent duplicate volume creation.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Indicates if the volume should be encrypted.</p>
    pub encrypted: ::std::option::Option<bool>,
    /// <p>Input/output operations per second for the volume.</p>
    pub iops: ::std::option::Option<i32>,
    /// <p>KMS key for volume encryption.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>Volume size in gigabytes.</p>
    pub size_in_gb: ::std::option::Option<i32>,
    /// <p>Source snapshot for volume creation.</p>
    pub snapshot_id: ::std::option::Option<::std::string::String>,
    /// <p>Metadata tags for the volume.</p>
    pub tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    /// <p>Volume throughput performance.</p>
    pub throughput: ::std::option::Option<i32>,
    /// <p>Type of EBS volume.</p>
    pub volume_type: ::std::option::Option<crate::types::VolumeTypeEnum>,
}
impl CreateVolumeInput {
    /// <p>Availability zone for the volume.</p>
    pub fn availability_zone(&self) -> ::std::option::Option<&str> {
        self.availability_zone.as_deref()
    }
    /// <p>Unique token to prevent duplicate volume creation.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Indicates if the volume should be encrypted.</p>
    pub fn encrypted(&self) -> ::std::option::Option<bool> {
        self.encrypted
    }
    /// <p>Input/output operations per second for the volume.</p>
    pub fn iops(&self) -> ::std::option::Option<i32> {
        self.iops
    }
    /// <p>KMS key for volume encryption.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>Volume size in gigabytes.</p>
    pub fn size_in_gb(&self) -> ::std::option::Option<i32> {
        self.size_in_gb
    }
    /// <p>Source snapshot for volume creation.</p>
    pub fn snapshot_id(&self) -> ::std::option::Option<&str> {
        self.snapshot_id.as_deref()
    }
    /// <p>Metadata tags for the volume.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_specifications.is_none()`.
    pub fn tag_specifications(&self) -> &[crate::types::TagSpecification] {
        self.tag_specifications.as_deref().unwrap_or_default()
    }
    /// <p>Volume throughput performance.</p>
    pub fn throughput(&self) -> ::std::option::Option<i32> {
        self.throughput
    }
    /// <p>Type of EBS volume.</p>
    pub fn volume_type(&self) -> ::std::option::Option<&crate::types::VolumeTypeEnum> {
        self.volume_type.as_ref()
    }
}
impl ::std::fmt::Debug for CreateVolumeInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateVolumeInput");
        formatter.field("availability_zone", &self.availability_zone);
        formatter.field("client_token", &"*** Sensitive Data Redacted ***");
        formatter.field("encrypted", &self.encrypted);
        formatter.field("iops", &self.iops);
        formatter.field("kms_key_id", &"*** Sensitive Data Redacted ***");
        formatter.field("size_in_gb", &self.size_in_gb);
        formatter.field("snapshot_id", &self.snapshot_id);
        formatter.field("tag_specifications", &self.tag_specifications);
        formatter.field("throughput", &self.throughput);
        formatter.field("volume_type", &self.volume_type);
        formatter.finish()
    }
}
impl CreateVolumeInput {
    /// Creates a new builder-style object to manufacture [`CreateVolumeInput`](crate::operation::create_volume::CreateVolumeInput).
    pub fn builder() -> crate::operation::create_volume::builders::CreateVolumeInputBuilder {
        crate::operation::create_volume::builders::CreateVolumeInputBuilder::default()
    }
}

/// A builder for [`CreateVolumeInput`](crate::operation::create_volume::CreateVolumeInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct CreateVolumeInputBuilder {
    pub(crate) availability_zone: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) encrypted: ::std::option::Option<bool>,
    pub(crate) iops: ::std::option::Option<i32>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) size_in_gb: ::std::option::Option<i32>,
    pub(crate) snapshot_id: ::std::option::Option<::std::string::String>,
    pub(crate) tag_specifications: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>,
    pub(crate) throughput: ::std::option::Option<i32>,
    pub(crate) volume_type: ::std::option::Option<crate::types::VolumeTypeEnum>,
}
impl CreateVolumeInputBuilder {
    /// <p>Availability zone for the volume.</p>
    /// This field is required.
    pub fn availability_zone(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.availability_zone = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Availability zone for the volume.</p>
    pub fn set_availability_zone(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.availability_zone = input;
        self
    }
    /// <p>Availability zone for the volume.</p>
    pub fn get_availability_zone(&self) -> &::std::option::Option<::std::string::String> {
        &self.availability_zone
    }
    /// <p>Unique token to prevent duplicate volume creation.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique token to prevent duplicate volume creation.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique token to prevent duplicate volume creation.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Indicates if the volume should be encrypted.</p>
    pub fn encrypted(mut self, input: bool) -> Self {
        self.encrypted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates if the volume should be encrypted.</p>
    pub fn set_encrypted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.encrypted = input;
        self
    }
    /// <p>Indicates if the volume should be encrypted.</p>
    pub fn get_encrypted(&self) -> &::std::option::Option<bool> {
        &self.encrypted
    }
    /// <p>Input/output operations per second for the volume.</p>
    pub fn iops(mut self, input: i32) -> Self {
        self.iops = ::std::option::Option::Some(input);
        self
    }
    /// <p>Input/output operations per second for the volume.</p>
    pub fn set_iops(mut self, input: ::std::option::Option<i32>) -> Self {
        self.iops = input;
        self
    }
    /// <p>Input/output operations per second for the volume.</p>
    pub fn get_iops(&self) -> &::std::option::Option<i32> {
        &self.iops
    }
    /// <p>KMS key for volume encryption.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>KMS key for volume encryption.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>KMS key for volume encryption.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>Volume size in gigabytes.</p>
    pub fn size_in_gb(mut self, input: i32) -> Self {
        self.size_in_gb = ::std::option::Option::Some(input);
        self
    }
    /// <p>Volume size in gigabytes.</p>
    pub fn set_size_in_gb(mut self, input: ::std::option::Option<i32>) -> Self {
        self.size_in_gb = input;
        self
    }
    /// <p>Volume size in gigabytes.</p>
    pub fn get_size_in_gb(&self) -> &::std::option::Option<i32> {
        &self.size_in_gb
    }
    /// <p>Source snapshot for volume creation.</p>
    pub fn snapshot_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.snapshot_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Source snapshot for volume creation.</p>
    pub fn set_snapshot_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.snapshot_id = input;
        self
    }
    /// <p>Source snapshot for volume creation.</p>
    pub fn get_snapshot_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.snapshot_id
    }
    /// Appends an item to `tag_specifications`.
    ///
    /// To override the contents of this collection use [`set_tag_specifications`](Self::set_tag_specifications).
    ///
    /// <p>Metadata tags for the volume.</p>
    pub fn tag_specifications(mut self, input: crate::types::TagSpecification) -> Self {
        let mut v = self.tag_specifications.unwrap_or_default();
        v.push(input);
        self.tag_specifications = ::std::option::Option::Some(v);
        self
    }
    /// <p>Metadata tags for the volume.</p>
    pub fn set_tag_specifications(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>>) -> Self {
        self.tag_specifications = input;
        self
    }
    /// <p>Metadata tags for the volume.</p>
    pub fn get_tag_specifications(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TagSpecification>> {
        &self.tag_specifications
    }
    /// <p>Volume throughput performance.</p>
    pub fn throughput(mut self, input: i32) -> Self {
        self.throughput = ::std::option::Option::Some(input);
        self
    }
    /// <p>Volume throughput performance.</p>
    pub fn set_throughput(mut self, input: ::std::option::Option<i32>) -> Self {
        self.throughput = input;
        self
    }
    /// <p>Volume throughput performance.</p>
    pub fn get_throughput(&self) -> &::std::option::Option<i32> {
        &self.throughput
    }
    /// <p>Type of EBS volume.</p>
    pub fn volume_type(mut self, input: crate::types::VolumeTypeEnum) -> Self {
        self.volume_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Type of EBS volume.</p>
    pub fn set_volume_type(mut self, input: ::std::option::Option<crate::types::VolumeTypeEnum>) -> Self {
        self.volume_type = input;
        self
    }
    /// <p>Type of EBS volume.</p>
    pub fn get_volume_type(&self) -> &::std::option::Option<crate::types::VolumeTypeEnum> {
        &self.volume_type
    }
    /// Consumes the builder and constructs a [`CreateVolumeInput`](crate::operation::create_volume::CreateVolumeInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_volume::CreateVolumeInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_volume::CreateVolumeInput {
            availability_zone: self.availability_zone,
            client_token: self.client_token,
            encrypted: self.encrypted,
            iops: self.iops,
            kms_key_id: self.kms_key_id,
            size_in_gb: self.size_in_gb,
            snapshot_id: self.snapshot_id,
            tag_specifications: self.tag_specifications,
            throughput: self.throughput,
            volume_type: self.volume_type,
        })
    }
}
impl ::std::fmt::Debug for CreateVolumeInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("CreateVolumeInputBuilder");
        formatter.field("availability_zone", &self.availability_zone);
        formatter.field("client_token", &"*** Sensitive Data Redacted ***");
        formatter.field("encrypted", &self.encrypted);
        formatter.field("iops", &self.iops);
        formatter.field("kms_key_id", &"*** Sensitive Data Redacted ***");
        formatter.field("size_in_gb", &self.size_in_gb);
        formatter.field("snapshot_id", &self.snapshot_id);
        formatter.field("tag_specifications", &self.tag_specifications);
        formatter.field("throughput", &self.throughput);
        formatter.field("volume_type", &self.volume_type);
        formatter.finish()
    }
}
