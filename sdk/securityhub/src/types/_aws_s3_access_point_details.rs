// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns configuration information about the specified Amazon S3 access point. S3 access points are named network endpoints that are attached to buckets that you can use to perform S3 object operations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsS3AccessPointDetails {
    /// <p>The Amazon Resource Name (ARN) of the access point.</p>
    pub access_point_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name or alias of the access point.</p>
    pub alias: ::std::option::Option<::std::string::String>,
    /// <p>The name of the S3 bucket associated with the specified access point.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services account ID associated with the S3 bucket associated with this access point.</p>
    pub bucket_account_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the specified access point.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether this access point allows access from the public internet.</p>
    pub network_origin: ::std::option::Option<::std::string::String>,
    /// <p>provides information about the Amazon S3 Public Access Block configuration for accounts.</p>
    pub public_access_block_configuration: ::std::option::Option<crate::types::AwsS3AccountPublicAccessBlockDetails>,
    /// <p>Contains the virtual private cloud (VPC) configuration for the specified access point.</p>
    pub vpc_configuration: ::std::option::Option<crate::types::AwsS3AccessPointVpcConfigurationDetails>,
}
impl AwsS3AccessPointDetails {
    /// <p>The Amazon Resource Name (ARN) of the access point.</p>
    pub fn access_point_arn(&self) -> ::std::option::Option<&str> {
        self.access_point_arn.as_deref()
    }
    /// <p>The name or alias of the access point.</p>
    pub fn alias(&self) -> ::std::option::Option<&str> {
        self.alias.as_deref()
    }
    /// <p>The name of the S3 bucket associated with the specified access point.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The Amazon Web Services account ID associated with the S3 bucket associated with this access point.</p>
    pub fn bucket_account_id(&self) -> ::std::option::Option<&str> {
        self.bucket_account_id.as_deref()
    }
    /// <p>The name of the specified access point.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Indicates whether this access point allows access from the public internet.</p>
    pub fn network_origin(&self) -> ::std::option::Option<&str> {
        self.network_origin.as_deref()
    }
    /// <p>provides information about the Amazon S3 Public Access Block configuration for accounts.</p>
    pub fn public_access_block_configuration(&self) -> ::std::option::Option<&crate::types::AwsS3AccountPublicAccessBlockDetails> {
        self.public_access_block_configuration.as_ref()
    }
    /// <p>Contains the virtual private cloud (VPC) configuration for the specified access point.</p>
    pub fn vpc_configuration(&self) -> ::std::option::Option<&crate::types::AwsS3AccessPointVpcConfigurationDetails> {
        self.vpc_configuration.as_ref()
    }
}
impl AwsS3AccessPointDetails {
    /// Creates a new builder-style object to manufacture [`AwsS3AccessPointDetails`](crate::types::AwsS3AccessPointDetails).
    pub fn builder() -> crate::types::builders::AwsS3AccessPointDetailsBuilder {
        crate::types::builders::AwsS3AccessPointDetailsBuilder::default()
    }
}

/// A builder for [`AwsS3AccessPointDetails`](crate::types::AwsS3AccessPointDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsS3AccessPointDetailsBuilder {
    pub(crate) access_point_arn: ::std::option::Option<::std::string::String>,
    pub(crate) alias: ::std::option::Option<::std::string::String>,
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) bucket_account_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) network_origin: ::std::option::Option<::std::string::String>,
    pub(crate) public_access_block_configuration: ::std::option::Option<crate::types::AwsS3AccountPublicAccessBlockDetails>,
    pub(crate) vpc_configuration: ::std::option::Option<crate::types::AwsS3AccessPointVpcConfigurationDetails>,
}
impl AwsS3AccessPointDetailsBuilder {
    /// <p>The Amazon Resource Name (ARN) of the access point.</p>
    pub fn access_point_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_point_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the access point.</p>
    pub fn set_access_point_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_point_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the access point.</p>
    pub fn get_access_point_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_point_arn
    }
    /// <p>The name or alias of the access point.</p>
    pub fn alias(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.alias = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or alias of the access point.</p>
    pub fn set_alias(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.alias = input;
        self
    }
    /// <p>The name or alias of the access point.</p>
    pub fn get_alias(&self) -> &::std::option::Option<::std::string::String> {
        &self.alias
    }
    /// <p>The name of the S3 bucket associated with the specified access point.</p>
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the S3 bucket associated with the specified access point.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of the S3 bucket associated with the specified access point.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The Amazon Web Services account ID associated with the S3 bucket associated with this access point.</p>
    pub fn bucket_account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID associated with the S3 bucket associated with this access point.</p>
    pub fn set_bucket_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID associated with the S3 bucket associated with this access point.</p>
    pub fn get_bucket_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_account_id
    }
    /// <p>The name of the specified access point.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the specified access point.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the specified access point.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>Indicates whether this access point allows access from the public internet.</p>
    pub fn network_origin(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.network_origin = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Indicates whether this access point allows access from the public internet.</p>
    pub fn set_network_origin(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.network_origin = input;
        self
    }
    /// <p>Indicates whether this access point allows access from the public internet.</p>
    pub fn get_network_origin(&self) -> &::std::option::Option<::std::string::String> {
        &self.network_origin
    }
    /// <p>provides information about the Amazon S3 Public Access Block configuration for accounts.</p>
    pub fn public_access_block_configuration(mut self, input: crate::types::AwsS3AccountPublicAccessBlockDetails) -> Self {
        self.public_access_block_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>provides information about the Amazon S3 Public Access Block configuration for accounts.</p>
    pub fn set_public_access_block_configuration(mut self, input: ::std::option::Option<crate::types::AwsS3AccountPublicAccessBlockDetails>) -> Self {
        self.public_access_block_configuration = input;
        self
    }
    /// <p>provides information about the Amazon S3 Public Access Block configuration for accounts.</p>
    pub fn get_public_access_block_configuration(&self) -> &::std::option::Option<crate::types::AwsS3AccountPublicAccessBlockDetails> {
        &self.public_access_block_configuration
    }
    /// <p>Contains the virtual private cloud (VPC) configuration for the specified access point.</p>
    pub fn vpc_configuration(mut self, input: crate::types::AwsS3AccessPointVpcConfigurationDetails) -> Self {
        self.vpc_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the virtual private cloud (VPC) configuration for the specified access point.</p>
    pub fn set_vpc_configuration(mut self, input: ::std::option::Option<crate::types::AwsS3AccessPointVpcConfigurationDetails>) -> Self {
        self.vpc_configuration = input;
        self
    }
    /// <p>Contains the virtual private cloud (VPC) configuration for the specified access point.</p>
    pub fn get_vpc_configuration(&self) -> &::std::option::Option<crate::types::AwsS3AccessPointVpcConfigurationDetails> {
        &self.vpc_configuration
    }
    /// Consumes the builder and constructs a [`AwsS3AccessPointDetails`](crate::types::AwsS3AccessPointDetails).
    pub fn build(self) -> crate::types::AwsS3AccessPointDetails {
        crate::types::AwsS3AccessPointDetails {
            access_point_arn: self.access_point_arn,
            alias: self.alias,
            bucket: self.bucket,
            bucket_account_id: self.bucket_account_id,
            name: self.name,
            network_origin: self.network_origin,
            public_access_block_configuration: self.public_access_block_configuration,
            vpc_configuration: self.vpc_configuration,
        }
    }
}
