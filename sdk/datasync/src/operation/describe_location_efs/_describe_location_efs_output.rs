// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>DescribeLocationEfsResponse</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLocationEfsOutput {
    /// <p>The ARN of the Amazon EFS file system location.</p>
    pub location_arn: ::std::option::Option<::std::string::String>,
    /// <p>The URL of the Amazon EFS file system location.</p>
    pub location_uri: ::std::option::Option<::std::string::String>,
    /// <p>The subnet and security groups that DataSync uses to connect to one of your Amazon EFS file system's <a href="https://docs.aws.amazon.com/efs/latest/ug/accessing-fs.html">mount targets</a>.</p>
    pub ec2_config: ::std::option::Option<crate::types::Ec2Config>,
    /// <p>The time that the location was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The ARN of the access point that DataSync uses to access the Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam">Accessing restricted file systems</a>.</p>
    pub access_point_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Identity and Access Management (IAM) role that allows DataSync to access your Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam-role">Creating a DataSync IAM role for file system access</a>.</p>
    pub file_system_access_role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Indicates whether DataSync uses Transport Layer Security (TLS) encryption when transferring data to or from the Amazon EFS file system.</p>
    pub in_transit_encryption: ::std::option::Option<crate::types::EfsInTransitEncryption>,
    _request_id: Option<String>,
}
impl DescribeLocationEfsOutput {
    /// <p>The ARN of the Amazon EFS file system location.</p>
    pub fn location_arn(&self) -> ::std::option::Option<&str> {
        self.location_arn.as_deref()
    }
    /// <p>The URL of the Amazon EFS file system location.</p>
    pub fn location_uri(&self) -> ::std::option::Option<&str> {
        self.location_uri.as_deref()
    }
    /// <p>The subnet and security groups that DataSync uses to connect to one of your Amazon EFS file system's <a href="https://docs.aws.amazon.com/efs/latest/ug/accessing-fs.html">mount targets</a>.</p>
    pub fn ec2_config(&self) -> ::std::option::Option<&crate::types::Ec2Config> {
        self.ec2_config.as_ref()
    }
    /// <p>The time that the location was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
    /// <p>The ARN of the access point that DataSync uses to access the Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam">Accessing restricted file systems</a>.</p>
    pub fn access_point_arn(&self) -> ::std::option::Option<&str> {
        self.access_point_arn.as_deref()
    }
    /// <p>The Identity and Access Management (IAM) role that allows DataSync to access your Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam-role">Creating a DataSync IAM role for file system access</a>.</p>
    pub fn file_system_access_role_arn(&self) -> ::std::option::Option<&str> {
        self.file_system_access_role_arn.as_deref()
    }
    /// <p>Indicates whether DataSync uses Transport Layer Security (TLS) encryption when transferring data to or from the Amazon EFS file system.</p>
    pub fn in_transit_encryption(&self) -> ::std::option::Option<&crate::types::EfsInTransitEncryption> {
        self.in_transit_encryption.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeLocationEfsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeLocationEfsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeLocationEfsOutput`](crate::operation::describe_location_efs::DescribeLocationEfsOutput).
    pub fn builder() -> crate::operation::describe_location_efs::builders::DescribeLocationEfsOutputBuilder {
        crate::operation::describe_location_efs::builders::DescribeLocationEfsOutputBuilder::default()
    }
}

/// A builder for [`DescribeLocationEfsOutput`](crate::operation::describe_location_efs::DescribeLocationEfsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLocationEfsOutputBuilder {
    pub(crate) location_arn: ::std::option::Option<::std::string::String>,
    pub(crate) location_uri: ::std::option::Option<::std::string::String>,
    pub(crate) ec2_config: ::std::option::Option<crate::types::Ec2Config>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) access_point_arn: ::std::option::Option<::std::string::String>,
    pub(crate) file_system_access_role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) in_transit_encryption: ::std::option::Option<crate::types::EfsInTransitEncryption>,
    _request_id: Option<String>,
}
impl DescribeLocationEfsOutputBuilder {
    /// <p>The ARN of the Amazon EFS file system location.</p>
    pub fn location_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Amazon EFS file system location.</p>
    pub fn set_location_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_arn = input;
        self
    }
    /// <p>The ARN of the Amazon EFS file system location.</p>
    pub fn get_location_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_arn
    }
    /// <p>The URL of the Amazon EFS file system location.</p>
    pub fn location_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the Amazon EFS file system location.</p>
    pub fn set_location_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_uri = input;
        self
    }
    /// <p>The URL of the Amazon EFS file system location.</p>
    pub fn get_location_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_uri
    }
    /// <p>The subnet and security groups that DataSync uses to connect to one of your Amazon EFS file system's <a href="https://docs.aws.amazon.com/efs/latest/ug/accessing-fs.html">mount targets</a>.</p>
    pub fn ec2_config(mut self, input: crate::types::Ec2Config) -> Self {
        self.ec2_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The subnet and security groups that DataSync uses to connect to one of your Amazon EFS file system's <a href="https://docs.aws.amazon.com/efs/latest/ug/accessing-fs.html">mount targets</a>.</p>
    pub fn set_ec2_config(mut self, input: ::std::option::Option<crate::types::Ec2Config>) -> Self {
        self.ec2_config = input;
        self
    }
    /// <p>The subnet and security groups that DataSync uses to connect to one of your Amazon EFS file system's <a href="https://docs.aws.amazon.com/efs/latest/ug/accessing-fs.html">mount targets</a>.</p>
    pub fn get_ec2_config(&self) -> &::std::option::Option<crate::types::Ec2Config> {
        &self.ec2_config
    }
    /// <p>The time that the location was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the location was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time that the location was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    /// <p>The ARN of the access point that DataSync uses to access the Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam">Accessing restricted file systems</a>.</p>
    pub fn access_point_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.access_point_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the access point that DataSync uses to access the Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam">Accessing restricted file systems</a>.</p>
    pub fn set_access_point_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.access_point_arn = input;
        self
    }
    /// <p>The ARN of the access point that DataSync uses to access the Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam">Accessing restricted file systems</a>.</p>
    pub fn get_access_point_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.access_point_arn
    }
    /// <p>The Identity and Access Management (IAM) role that allows DataSync to access your Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam-role">Creating a DataSync IAM role for file system access</a>.</p>
    pub fn file_system_access_role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_access_role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Identity and Access Management (IAM) role that allows DataSync to access your Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam-role">Creating a DataSync IAM role for file system access</a>.</p>
    pub fn set_file_system_access_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_access_role_arn = input;
        self
    }
    /// <p>The Identity and Access Management (IAM) role that allows DataSync to access your Amazon EFS file system.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html#create-efs-location-iam-role">Creating a DataSync IAM role for file system access</a>.</p>
    pub fn get_file_system_access_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_access_role_arn
    }
    /// <p>Indicates whether DataSync uses Transport Layer Security (TLS) encryption when transferring data to or from the Amazon EFS file system.</p>
    pub fn in_transit_encryption(mut self, input: crate::types::EfsInTransitEncryption) -> Self {
        self.in_transit_encryption = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether DataSync uses Transport Layer Security (TLS) encryption when transferring data to or from the Amazon EFS file system.</p>
    pub fn set_in_transit_encryption(mut self, input: ::std::option::Option<crate::types::EfsInTransitEncryption>) -> Self {
        self.in_transit_encryption = input;
        self
    }
    /// <p>Indicates whether DataSync uses Transport Layer Security (TLS) encryption when transferring data to or from the Amazon EFS file system.</p>
    pub fn get_in_transit_encryption(&self) -> &::std::option::Option<crate::types::EfsInTransitEncryption> {
        &self.in_transit_encryption
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeLocationEfsOutput`](crate::operation::describe_location_efs::DescribeLocationEfsOutput).
    pub fn build(self) -> crate::operation::describe_location_efs::DescribeLocationEfsOutput {
        crate::operation::describe_location_efs::DescribeLocationEfsOutput {
            location_arn: self.location_arn,
            location_uri: self.location_uri,
            ec2_config: self.ec2_config,
            creation_time: self.creation_time,
            access_point_arn: self.access_point_arn,
            file_system_access_role_arn: self.file_system_access_role_arn,
            in_transit_encryption: self.in_transit_encryption,
            _request_id: self._request_id,
        }
    }
}
