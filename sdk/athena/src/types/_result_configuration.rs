// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The location in Amazon S3 where query and calculation results are stored and the encryption option, if any, used for query and calculation results. These are known as "client-side settings". If workgroup settings override client-side settings, then the query uses the workgroup settings.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResultConfiguration {
    /// <p>The location in Amazon S3 where your query and calculation results are stored, such as <code>s3://path/to/query/bucket/</code>. To run the query, you must specify the query results location using one of the ways: either for individual queries using either this setting (client-side), or in the workgroup, using <code>WorkGroupConfiguration</code>. If none of them is set, Athena issues an error that no output location is provided. If workgroup settings override client-side settings, then the query uses the settings specified for the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code>.</p>
    pub output_location: ::std::option::Option<::std::string::String>,
    /// <p>If query and calculation results are encrypted in Amazon S3, indicates the encryption option used (for example, <code>SSE_KMS</code> or <code>CSE_KMS</code>) and key information. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the encryption configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub encryption_configuration: ::std::option::Option<crate::types::EncryptionConfiguration>,
    /// <p>The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by <code>ResultConfiguration$OutputLocation</code>. If set, Athena uses the value for <code>ExpectedBucketOwner</code> when it makes Amazon S3 calls to your specified output location. If the <code>ExpectedBucketOwner</code> Amazon Web Services account ID does not match the actual owner of the Amazon S3 bucket, the call fails with a permissions error.</p>
    /// <p>This is a client-side setting. If workgroup settings override client-side settings, then the query uses the <code>ExpectedBucketOwner</code> setting that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub expected_bucket_owner: ::std::option::Option<::std::string::String>,
    /// <p>Indicates that an Amazon S3 canned ACL should be set to control ownership of stored query results. Currently the only supported canned ACL is <code>BUCKET_OWNER_FULL_CONTROL</code>. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the ACL configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. For more information, see <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub acl_configuration: ::std::option::Option<crate::types::AclConfiguration>,
}
impl ResultConfiguration {
    /// <p>The location in Amazon S3 where your query and calculation results are stored, such as <code>s3://path/to/query/bucket/</code>. To run the query, you must specify the query results location using one of the ways: either for individual queries using either this setting (client-side), or in the workgroup, using <code>WorkGroupConfiguration</code>. If none of them is set, Athena issues an error that no output location is provided. If workgroup settings override client-side settings, then the query uses the settings specified for the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code>.</p>
    pub fn output_location(&self) -> ::std::option::Option<&str> {
        self.output_location.as_deref()
    }
    /// <p>If query and calculation results are encrypted in Amazon S3, indicates the encryption option used (for example, <code>SSE_KMS</code> or <code>CSE_KMS</code>) and key information. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the encryption configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn encryption_configuration(&self) -> ::std::option::Option<&crate::types::EncryptionConfiguration> {
        self.encryption_configuration.as_ref()
    }
    /// <p>The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by <code>ResultConfiguration$OutputLocation</code>. If set, Athena uses the value for <code>ExpectedBucketOwner</code> when it makes Amazon S3 calls to your specified output location. If the <code>ExpectedBucketOwner</code> Amazon Web Services account ID does not match the actual owner of the Amazon S3 bucket, the call fails with a permissions error.</p>
    /// <p>This is a client-side setting. If workgroup settings override client-side settings, then the query uses the <code>ExpectedBucketOwner</code> setting that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn expected_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.expected_bucket_owner.as_deref()
    }
    /// <p>Indicates that an Amazon S3 canned ACL should be set to control ownership of stored query results. Currently the only supported canned ACL is <code>BUCKET_OWNER_FULL_CONTROL</code>. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the ACL configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. For more information, see <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn acl_configuration(&self) -> ::std::option::Option<&crate::types::AclConfiguration> {
        self.acl_configuration.as_ref()
    }
}
impl ResultConfiguration {
    /// Creates a new builder-style object to manufacture [`ResultConfiguration`](crate::types::ResultConfiguration).
    pub fn builder() -> crate::types::builders::ResultConfigurationBuilder {
        crate::types::builders::ResultConfigurationBuilder::default()
    }
}

/// A builder for [`ResultConfiguration`](crate::types::ResultConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResultConfigurationBuilder {
    pub(crate) output_location: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_configuration: ::std::option::Option<crate::types::EncryptionConfiguration>,
    pub(crate) expected_bucket_owner: ::std::option::Option<::std::string::String>,
    pub(crate) acl_configuration: ::std::option::Option<crate::types::AclConfiguration>,
}
impl ResultConfigurationBuilder {
    /// <p>The location in Amazon S3 where your query and calculation results are stored, such as <code>s3://path/to/query/bucket/</code>. To run the query, you must specify the query results location using one of the ways: either for individual queries using either this setting (client-side), or in the workgroup, using <code>WorkGroupConfiguration</code>. If none of them is set, Athena issues an error that no output location is provided. If workgroup settings override client-side settings, then the query uses the settings specified for the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code>.</p>
    pub fn output_location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.output_location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The location in Amazon S3 where your query and calculation results are stored, such as <code>s3://path/to/query/bucket/</code>. To run the query, you must specify the query results location using one of the ways: either for individual queries using either this setting (client-side), or in the workgroup, using <code>WorkGroupConfiguration</code>. If none of them is set, Athena issues an error that no output location is provided. If workgroup settings override client-side settings, then the query uses the settings specified for the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code>.</p>
    pub fn set_output_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.output_location = input;
        self
    }
    /// <p>The location in Amazon S3 where your query and calculation results are stored, such as <code>s3://path/to/query/bucket/</code>. To run the query, you must specify the query results location using one of the ways: either for individual queries using either this setting (client-side), or in the workgroup, using <code>WorkGroupConfiguration</code>. If none of them is set, Athena issues an error that no output location is provided. If workgroup settings override client-side settings, then the query uses the settings specified for the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code>.</p>
    pub fn get_output_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.output_location
    }
    /// <p>If query and calculation results are encrypted in Amazon S3, indicates the encryption option used (for example, <code>SSE_KMS</code> or <code>CSE_KMS</code>) and key information. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the encryption configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn encryption_configuration(mut self, input: crate::types::EncryptionConfiguration) -> Self {
        self.encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>If query and calculation results are encrypted in Amazon S3, indicates the encryption option used (for example, <code>SSE_KMS</code> or <code>CSE_KMS</code>) and key information. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the encryption configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn set_encryption_configuration(mut self, input: ::std::option::Option<crate::types::EncryptionConfiguration>) -> Self {
        self.encryption_configuration = input;
        self
    }
    /// <p>If query and calculation results are encrypted in Amazon S3, indicates the encryption option used (for example, <code>SSE_KMS</code> or <code>CSE_KMS</code>) and key information. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the encryption configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn get_encryption_configuration(&self) -> &::std::option::Option<crate::types::EncryptionConfiguration> {
        &self.encryption_configuration
    }
    /// <p>The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by <code>ResultConfiguration$OutputLocation</code>. If set, Athena uses the value for <code>ExpectedBucketOwner</code> when it makes Amazon S3 calls to your specified output location. If the <code>ExpectedBucketOwner</code> Amazon Web Services account ID does not match the actual owner of the Amazon S3 bucket, the call fails with a permissions error.</p>
    /// <p>This is a client-side setting. If workgroup settings override client-side settings, then the query uses the <code>ExpectedBucketOwner</code> setting that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn expected_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by <code>ResultConfiguration$OutputLocation</code>. If set, Athena uses the value for <code>ExpectedBucketOwner</code> when it makes Amazon S3 calls to your specified output location. If the <code>ExpectedBucketOwner</code> Amazon Web Services account ID does not match the actual owner of the Amazon S3 bucket, the call fails with a permissions error.</p>
    /// <p>This is a client-side setting. If workgroup settings override client-side settings, then the query uses the <code>ExpectedBucketOwner</code> setting that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn set_expected_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_bucket_owner = input;
        self
    }
    /// <p>The Amazon Web Services account ID that you expect to be the owner of the Amazon S3 bucket specified by <code>ResultConfiguration$OutputLocation</code>. If set, Athena uses the value for <code>ExpectedBucketOwner</code> when it makes Amazon S3 calls to your specified output location. If the <code>ExpectedBucketOwner</code> Amazon Web Services account ID does not match the actual owner of the Amazon S3 bucket, the call fails with a permissions error.</p>
    /// <p>This is a client-side setting. If workgroup settings override client-side settings, then the query uses the <code>ExpectedBucketOwner</code> setting that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. See <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn get_expected_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_bucket_owner
    }
    /// <p>Indicates that an Amazon S3 canned ACL should be set to control ownership of stored query results. Currently the only supported canned ACL is <code>BUCKET_OWNER_FULL_CONTROL</code>. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the ACL configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. For more information, see <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn acl_configuration(mut self, input: crate::types::AclConfiguration) -> Self {
        self.acl_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates that an Amazon S3 canned ACL should be set to control ownership of stored query results. Currently the only supported canned ACL is <code>BUCKET_OWNER_FULL_CONTROL</code>. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the ACL configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. For more information, see <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn set_acl_configuration(mut self, input: ::std::option::Option<crate::types::AclConfiguration>) -> Self {
        self.acl_configuration = input;
        self
    }
    /// <p>Indicates that an Amazon S3 canned ACL should be set to control ownership of stored query results. Currently the only supported canned ACL is <code>BUCKET_OWNER_FULL_CONTROL</code>. This is a client-side setting. If workgroup settings override client-side settings, then the query uses the ACL configuration that is specified for the workgroup, and also uses the location for storing query results specified in the workgroup. For more information, see <code>WorkGroupConfiguration$EnforceWorkGroupConfiguration</code> and <a href="https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings-override.html">Workgroup Settings Override Client-Side Settings</a>.</p>
    pub fn get_acl_configuration(&self) -> &::std::option::Option<crate::types::AclConfiguration> {
        &self.acl_configuration
    }
    /// Consumes the builder and constructs a [`ResultConfiguration`](crate::types::ResultConfiguration).
    pub fn build(self) -> crate::types::ResultConfiguration {
        crate::types::ResultConfiguration {
            output_location: self.output_location,
            encryption_configuration: self.encryption_configuration,
            expected_bucket_owner: self.expected_bucket_owner,
            acl_configuration: self.acl_configuration,
        }
    }
}
