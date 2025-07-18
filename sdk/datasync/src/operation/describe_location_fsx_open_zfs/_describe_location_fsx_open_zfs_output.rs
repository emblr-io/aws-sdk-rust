// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeLocationFsxOpenZfsOutput {
    /// <p>The ARN of the FSx for OpenZFS location that was described.</p>
    pub location_arn: ::std::option::Option<::std::string::String>,
    /// <p>The uniform resource identifier (URI) of the FSx for OpenZFS location that was described.</p>
    /// <p>Example: <code>fsxz://us-west-2.fs-1234567890abcdef02/fsx/folderA/folder</code></p>
    pub location_uri: ::std::option::Option<::std::string::String>,
    /// <p>The ARNs of the security groups that are configured for the FSx for OpenZFS file system.</p>
    pub security_group_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The type of protocol that DataSync uses to access your file system.</p>
    pub protocol: ::std::option::Option<crate::types::FsxProtocol>,
    /// <p>The time that the FSx for OpenZFS location was created.</p>
    pub creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeLocationFsxOpenZfsOutput {
    /// <p>The ARN of the FSx for OpenZFS location that was described.</p>
    pub fn location_arn(&self) -> ::std::option::Option<&str> {
        self.location_arn.as_deref()
    }
    /// <p>The uniform resource identifier (URI) of the FSx for OpenZFS location that was described.</p>
    /// <p>Example: <code>fsxz://us-west-2.fs-1234567890abcdef02/fsx/folderA/folder</code></p>
    pub fn location_uri(&self) -> ::std::option::Option<&str> {
        self.location_uri.as_deref()
    }
    /// <p>The ARNs of the security groups that are configured for the FSx for OpenZFS file system.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.security_group_arns.is_none()`.
    pub fn security_group_arns(&self) -> &[::std::string::String] {
        self.security_group_arns.as_deref().unwrap_or_default()
    }
    /// <p>The type of protocol that DataSync uses to access your file system.</p>
    pub fn protocol(&self) -> ::std::option::Option<&crate::types::FsxProtocol> {
        self.protocol.as_ref()
    }
    /// <p>The time that the FSx for OpenZFS location was created.</p>
    pub fn creation_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeLocationFsxOpenZfsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeLocationFsxOpenZfsOutput {
    /// Creates a new builder-style object to manufacture [`DescribeLocationFsxOpenZfsOutput`](crate::operation::describe_location_fsx_open_zfs::DescribeLocationFsxOpenZfsOutput).
    pub fn builder() -> crate::operation::describe_location_fsx_open_zfs::builders::DescribeLocationFsxOpenZfsOutputBuilder {
        crate::operation::describe_location_fsx_open_zfs::builders::DescribeLocationFsxOpenZfsOutputBuilder::default()
    }
}

/// A builder for [`DescribeLocationFsxOpenZfsOutput`](crate::operation::describe_location_fsx_open_zfs::DescribeLocationFsxOpenZfsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeLocationFsxOpenZfsOutputBuilder {
    pub(crate) location_arn: ::std::option::Option<::std::string::String>,
    pub(crate) location_uri: ::std::option::Option<::std::string::String>,
    pub(crate) security_group_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) protocol: ::std::option::Option<crate::types::FsxProtocol>,
    pub(crate) creation_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl DescribeLocationFsxOpenZfsOutputBuilder {
    /// <p>The ARN of the FSx for OpenZFS location that was described.</p>
    pub fn location_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the FSx for OpenZFS location that was described.</p>
    pub fn set_location_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_arn = input;
        self
    }
    /// <p>The ARN of the FSx for OpenZFS location that was described.</p>
    pub fn get_location_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_arn
    }
    /// <p>The uniform resource identifier (URI) of the FSx for OpenZFS location that was described.</p>
    /// <p>Example: <code>fsxz://us-west-2.fs-1234567890abcdef02/fsx/folderA/folder</code></p>
    pub fn location_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The uniform resource identifier (URI) of the FSx for OpenZFS location that was described.</p>
    /// <p>Example: <code>fsxz://us-west-2.fs-1234567890abcdef02/fsx/folderA/folder</code></p>
    pub fn set_location_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_uri = input;
        self
    }
    /// <p>The uniform resource identifier (URI) of the FSx for OpenZFS location that was described.</p>
    /// <p>Example: <code>fsxz://us-west-2.fs-1234567890abcdef02/fsx/folderA/folder</code></p>
    pub fn get_location_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_uri
    }
    /// Appends an item to `security_group_arns`.
    ///
    /// To override the contents of this collection use [`set_security_group_arns`](Self::set_security_group_arns).
    ///
    /// <p>The ARNs of the security groups that are configured for the FSx for OpenZFS file system.</p>
    pub fn security_group_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.security_group_arns.unwrap_or_default();
        v.push(input.into());
        self.security_group_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARNs of the security groups that are configured for the FSx for OpenZFS file system.</p>
    pub fn set_security_group_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.security_group_arns = input;
        self
    }
    /// <p>The ARNs of the security groups that are configured for the FSx for OpenZFS file system.</p>
    pub fn get_security_group_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.security_group_arns
    }
    /// <p>The type of protocol that DataSync uses to access your file system.</p>
    pub fn protocol(mut self, input: crate::types::FsxProtocol) -> Self {
        self.protocol = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of protocol that DataSync uses to access your file system.</p>
    pub fn set_protocol(mut self, input: ::std::option::Option<crate::types::FsxProtocol>) -> Self {
        self.protocol = input;
        self
    }
    /// <p>The type of protocol that DataSync uses to access your file system.</p>
    pub fn get_protocol(&self) -> &::std::option::Option<crate::types::FsxProtocol> {
        &self.protocol
    }
    /// <p>The time that the FSx for OpenZFS location was created.</p>
    pub fn creation_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time that the FSx for OpenZFS location was created.</p>
    pub fn set_creation_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_time = input;
        self
    }
    /// <p>The time that the FSx for OpenZFS location was created.</p>
    pub fn get_creation_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeLocationFsxOpenZfsOutput`](crate::operation::describe_location_fsx_open_zfs::DescribeLocationFsxOpenZfsOutput).
    pub fn build(self) -> crate::operation::describe_location_fsx_open_zfs::DescribeLocationFsxOpenZfsOutput {
        crate::operation::describe_location_fsx_open_zfs::DescribeLocationFsxOpenZfsOutput {
            location_arn: self.location_arn,
            location_uri: self.location_uri,
            security_group_arns: self.security_group_arns,
            protocol: self.protocol,
            creation_time: self.creation_time,
            _request_id: self._request_id,
        }
    }
}
