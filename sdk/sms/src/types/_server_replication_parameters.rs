// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The replication parameters for replicating a server.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ServerReplicationParameters {
    /// <p>The seed time for creating a replication job for the server.</p>
    pub seed_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The frequency of creating replication jobs for the server.</p>
    pub frequency: ::std::option::Option<i32>,
    /// <p>Indicates whether to run the replication job one time.</p>
    pub run_once: ::std::option::Option<bool>,
    /// <p>The license type for creating a replication job for the server.</p>
    pub license_type: ::std::option::Option<crate::types::LicenseType>,
    /// <p>The number of recent AMIs to keep when creating a replication job for this server.</p>
    pub number_of_recent_amis_to_keep: ::std::option::Option<i32>,
    /// <p>Indicates whether the replication job produces encrypted AMIs.</p>
    pub encrypted: ::std::option::Option<bool>,
    /// <p>The ID of the KMS key for replication jobs that produce encrypted AMIs. This value can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>KMS key ID</p></li>
    /// <li>
    /// <p>KMS key alias</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key ID</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key alias</p></li>
    /// </ul>
    /// <p>If encrypted is enabled but a KMS key ID is not specified, the customer's default KMS key for Amazon EBS is used.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
}
impl ServerReplicationParameters {
    /// <p>The seed time for creating a replication job for the server.</p>
    pub fn seed_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.seed_time.as_ref()
    }
    /// <p>The frequency of creating replication jobs for the server.</p>
    pub fn frequency(&self) -> ::std::option::Option<i32> {
        self.frequency
    }
    /// <p>Indicates whether to run the replication job one time.</p>
    pub fn run_once(&self) -> ::std::option::Option<bool> {
        self.run_once
    }
    /// <p>The license type for creating a replication job for the server.</p>
    pub fn license_type(&self) -> ::std::option::Option<&crate::types::LicenseType> {
        self.license_type.as_ref()
    }
    /// <p>The number of recent AMIs to keep when creating a replication job for this server.</p>
    pub fn number_of_recent_amis_to_keep(&self) -> ::std::option::Option<i32> {
        self.number_of_recent_amis_to_keep
    }
    /// <p>Indicates whether the replication job produces encrypted AMIs.</p>
    pub fn encrypted(&self) -> ::std::option::Option<bool> {
        self.encrypted
    }
    /// <p>The ID of the KMS key for replication jobs that produce encrypted AMIs. This value can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>KMS key ID</p></li>
    /// <li>
    /// <p>KMS key alias</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key ID</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key alias</p></li>
    /// </ul>
    /// <p>If encrypted is enabled but a KMS key ID is not specified, the customer's default KMS key for Amazon EBS is used.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
}
impl ServerReplicationParameters {
    /// Creates a new builder-style object to manufacture [`ServerReplicationParameters`](crate::types::ServerReplicationParameters).
    pub fn builder() -> crate::types::builders::ServerReplicationParametersBuilder {
        crate::types::builders::ServerReplicationParametersBuilder::default()
    }
}

/// A builder for [`ServerReplicationParameters`](crate::types::ServerReplicationParameters).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ServerReplicationParametersBuilder {
    pub(crate) seed_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) frequency: ::std::option::Option<i32>,
    pub(crate) run_once: ::std::option::Option<bool>,
    pub(crate) license_type: ::std::option::Option<crate::types::LicenseType>,
    pub(crate) number_of_recent_amis_to_keep: ::std::option::Option<i32>,
    pub(crate) encrypted: ::std::option::Option<bool>,
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
}
impl ServerReplicationParametersBuilder {
    /// <p>The seed time for creating a replication job for the server.</p>
    pub fn seed_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.seed_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The seed time for creating a replication job for the server.</p>
    pub fn set_seed_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.seed_time = input;
        self
    }
    /// <p>The seed time for creating a replication job for the server.</p>
    pub fn get_seed_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.seed_time
    }
    /// <p>The frequency of creating replication jobs for the server.</p>
    pub fn frequency(mut self, input: i32) -> Self {
        self.frequency = ::std::option::Option::Some(input);
        self
    }
    /// <p>The frequency of creating replication jobs for the server.</p>
    pub fn set_frequency(mut self, input: ::std::option::Option<i32>) -> Self {
        self.frequency = input;
        self
    }
    /// <p>The frequency of creating replication jobs for the server.</p>
    pub fn get_frequency(&self) -> &::std::option::Option<i32> {
        &self.frequency
    }
    /// <p>Indicates whether to run the replication job one time.</p>
    pub fn run_once(mut self, input: bool) -> Self {
        self.run_once = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to run the replication job one time.</p>
    pub fn set_run_once(mut self, input: ::std::option::Option<bool>) -> Self {
        self.run_once = input;
        self
    }
    /// <p>Indicates whether to run the replication job one time.</p>
    pub fn get_run_once(&self) -> &::std::option::Option<bool> {
        &self.run_once
    }
    /// <p>The license type for creating a replication job for the server.</p>
    pub fn license_type(mut self, input: crate::types::LicenseType) -> Self {
        self.license_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The license type for creating a replication job for the server.</p>
    pub fn set_license_type(mut self, input: ::std::option::Option<crate::types::LicenseType>) -> Self {
        self.license_type = input;
        self
    }
    /// <p>The license type for creating a replication job for the server.</p>
    pub fn get_license_type(&self) -> &::std::option::Option<crate::types::LicenseType> {
        &self.license_type
    }
    /// <p>The number of recent AMIs to keep when creating a replication job for this server.</p>
    pub fn number_of_recent_amis_to_keep(mut self, input: i32) -> Self {
        self.number_of_recent_amis_to_keep = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of recent AMIs to keep when creating a replication job for this server.</p>
    pub fn set_number_of_recent_amis_to_keep(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_recent_amis_to_keep = input;
        self
    }
    /// <p>The number of recent AMIs to keep when creating a replication job for this server.</p>
    pub fn get_number_of_recent_amis_to_keep(&self) -> &::std::option::Option<i32> {
        &self.number_of_recent_amis_to_keep
    }
    /// <p>Indicates whether the replication job produces encrypted AMIs.</p>
    pub fn encrypted(mut self, input: bool) -> Self {
        self.encrypted = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the replication job produces encrypted AMIs.</p>
    pub fn set_encrypted(mut self, input: ::std::option::Option<bool>) -> Self {
        self.encrypted = input;
        self
    }
    /// <p>Indicates whether the replication job produces encrypted AMIs.</p>
    pub fn get_encrypted(&self) -> &::std::option::Option<bool> {
        &self.encrypted
    }
    /// <p>The ID of the KMS key for replication jobs that produce encrypted AMIs. This value can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>KMS key ID</p></li>
    /// <li>
    /// <p>KMS key alias</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key ID</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key alias</p></li>
    /// </ul>
    /// <p>If encrypted is enabled but a KMS key ID is not specified, the customer's default KMS key for Amazon EBS is used.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the KMS key for replication jobs that produce encrypted AMIs. This value can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>KMS key ID</p></li>
    /// <li>
    /// <p>KMS key alias</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key ID</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key alias</p></li>
    /// </ul>
    /// <p>If encrypted is enabled but a KMS key ID is not specified, the customer's default KMS key for Amazon EBS is used.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>The ID of the KMS key for replication jobs that produce encrypted AMIs. This value can be any of the following:</p>
    /// <ul>
    /// <li>
    /// <p>KMS key ID</p></li>
    /// <li>
    /// <p>KMS key alias</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key ID</p></li>
    /// <li>
    /// <p>ARN referring to the KMS key alias</p></li>
    /// </ul>
    /// <p>If encrypted is enabled but a KMS key ID is not specified, the customer's default KMS key for Amazon EBS is used.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// Consumes the builder and constructs a [`ServerReplicationParameters`](crate::types::ServerReplicationParameters).
    pub fn build(self) -> crate::types::ServerReplicationParameters {
        crate::types::ServerReplicationParameters {
            seed_time: self.seed_time,
            frequency: self.frequency,
            run_once: self.run_once,
            license_type: self.license_type,
            number_of_recent_amis_to_keep: self.number_of_recent_amis_to_keep,
            encrypted: self.encrypted,
            kms_key_id: self.kms_key_id,
        }
    }
}
