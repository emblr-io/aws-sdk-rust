// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing an error when an asynchronous operation fails.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ErrorDetail {
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>SubnetNotFound</b>: We couldn't find one of the subnets associated with the cluster.</p></li>
    /// <li>
    /// <p><b>SecurityGroupNotFound</b>: We couldn't find one of the security groups associated with the cluster.</p></li>
    /// <li>
    /// <p><b>EniLimitReached</b>: You have reached the elastic network interface limit for your account.</p></li>
    /// <li>
    /// <p><b>IpNotAvailable</b>: A subnet associated with the cluster doesn't have any available IP addresses.</p></li>
    /// <li>
    /// <p><b>AccessDenied</b>: You don't have permissions to perform the specified operation.</p></li>
    /// <li>
    /// <p><b>OperationNotPermitted</b>: The service role associated with the cluster doesn't have the required access permissions for Amazon EKS.</p></li>
    /// <li>
    /// <p><b>VpcIdNotFound</b>: We couldn't find the VPC associated with the cluster.</p></li>
    /// </ul>
    pub error_code: ::std::option::Option<crate::types::ErrorCode>,
    /// <p>A more complete description of the error.</p>
    pub error_message: ::std::option::Option<::std::string::String>,
    /// <p>An optional field that contains the resource IDs associated with the error.</p>
    pub resource_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ErrorDetail {
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>SubnetNotFound</b>: We couldn't find one of the subnets associated with the cluster.</p></li>
    /// <li>
    /// <p><b>SecurityGroupNotFound</b>: We couldn't find one of the security groups associated with the cluster.</p></li>
    /// <li>
    /// <p><b>EniLimitReached</b>: You have reached the elastic network interface limit for your account.</p></li>
    /// <li>
    /// <p><b>IpNotAvailable</b>: A subnet associated with the cluster doesn't have any available IP addresses.</p></li>
    /// <li>
    /// <p><b>AccessDenied</b>: You don't have permissions to perform the specified operation.</p></li>
    /// <li>
    /// <p><b>OperationNotPermitted</b>: The service role associated with the cluster doesn't have the required access permissions for Amazon EKS.</p></li>
    /// <li>
    /// <p><b>VpcIdNotFound</b>: We couldn't find the VPC associated with the cluster.</p></li>
    /// </ul>
    pub fn error_code(&self) -> ::std::option::Option<&crate::types::ErrorCode> {
        self.error_code.as_ref()
    }
    /// <p>A more complete description of the error.</p>
    pub fn error_message(&self) -> ::std::option::Option<&str> {
        self.error_message.as_deref()
    }
    /// <p>An optional field that contains the resource IDs associated with the error.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_ids.is_none()`.
    pub fn resource_ids(&self) -> &[::std::string::String] {
        self.resource_ids.as_deref().unwrap_or_default()
    }
}
impl ErrorDetail {
    /// Creates a new builder-style object to manufacture [`ErrorDetail`](crate::types::ErrorDetail).
    pub fn builder() -> crate::types::builders::ErrorDetailBuilder {
        crate::types::builders::ErrorDetailBuilder::default()
    }
}

/// A builder for [`ErrorDetail`](crate::types::ErrorDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ErrorDetailBuilder {
    pub(crate) error_code: ::std::option::Option<crate::types::ErrorCode>,
    pub(crate) error_message: ::std::option::Option<::std::string::String>,
    pub(crate) resource_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl ErrorDetailBuilder {
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>SubnetNotFound</b>: We couldn't find one of the subnets associated with the cluster.</p></li>
    /// <li>
    /// <p><b>SecurityGroupNotFound</b>: We couldn't find one of the security groups associated with the cluster.</p></li>
    /// <li>
    /// <p><b>EniLimitReached</b>: You have reached the elastic network interface limit for your account.</p></li>
    /// <li>
    /// <p><b>IpNotAvailable</b>: A subnet associated with the cluster doesn't have any available IP addresses.</p></li>
    /// <li>
    /// <p><b>AccessDenied</b>: You don't have permissions to perform the specified operation.</p></li>
    /// <li>
    /// <p><b>OperationNotPermitted</b>: The service role associated with the cluster doesn't have the required access permissions for Amazon EKS.</p></li>
    /// <li>
    /// <p><b>VpcIdNotFound</b>: We couldn't find the VPC associated with the cluster.</p></li>
    /// </ul>
    pub fn error_code(mut self, input: crate::types::ErrorCode) -> Self {
        self.error_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>SubnetNotFound</b>: We couldn't find one of the subnets associated with the cluster.</p></li>
    /// <li>
    /// <p><b>SecurityGroupNotFound</b>: We couldn't find one of the security groups associated with the cluster.</p></li>
    /// <li>
    /// <p><b>EniLimitReached</b>: You have reached the elastic network interface limit for your account.</p></li>
    /// <li>
    /// <p><b>IpNotAvailable</b>: A subnet associated with the cluster doesn't have any available IP addresses.</p></li>
    /// <li>
    /// <p><b>AccessDenied</b>: You don't have permissions to perform the specified operation.</p></li>
    /// <li>
    /// <p><b>OperationNotPermitted</b>: The service role associated with the cluster doesn't have the required access permissions for Amazon EKS.</p></li>
    /// <li>
    /// <p><b>VpcIdNotFound</b>: We couldn't find the VPC associated with the cluster.</p></li>
    /// </ul>
    pub fn set_error_code(mut self, input: ::std::option::Option<crate::types::ErrorCode>) -> Self {
        self.error_code = input;
        self
    }
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>SubnetNotFound</b>: We couldn't find one of the subnets associated with the cluster.</p></li>
    /// <li>
    /// <p><b>SecurityGroupNotFound</b>: We couldn't find one of the security groups associated with the cluster.</p></li>
    /// <li>
    /// <p><b>EniLimitReached</b>: You have reached the elastic network interface limit for your account.</p></li>
    /// <li>
    /// <p><b>IpNotAvailable</b>: A subnet associated with the cluster doesn't have any available IP addresses.</p></li>
    /// <li>
    /// <p><b>AccessDenied</b>: You don't have permissions to perform the specified operation.</p></li>
    /// <li>
    /// <p><b>OperationNotPermitted</b>: The service role associated with the cluster doesn't have the required access permissions for Amazon EKS.</p></li>
    /// <li>
    /// <p><b>VpcIdNotFound</b>: We couldn't find the VPC associated with the cluster.</p></li>
    /// </ul>
    pub fn get_error_code(&self) -> &::std::option::Option<crate::types::ErrorCode> {
        &self.error_code
    }
    /// <p>A more complete description of the error.</p>
    pub fn error_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A more complete description of the error.</p>
    pub fn set_error_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error_message = input;
        self
    }
    /// <p>A more complete description of the error.</p>
    pub fn get_error_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.error_message
    }
    /// Appends an item to `resource_ids`.
    ///
    /// To override the contents of this collection use [`set_resource_ids`](Self::set_resource_ids).
    ///
    /// <p>An optional field that contains the resource IDs associated with the error.</p>
    pub fn resource_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_ids.unwrap_or_default();
        v.push(input.into());
        self.resource_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>An optional field that contains the resource IDs associated with the error.</p>
    pub fn set_resource_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_ids = input;
        self
    }
    /// <p>An optional field that contains the resource IDs associated with the error.</p>
    pub fn get_resource_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_ids
    }
    /// Consumes the builder and constructs a [`ErrorDetail`](crate::types::ErrorDetail).
    pub fn build(self) -> crate::types::ErrorDetail {
        crate::types::ErrorDetail {
            error_code: self.error_code,
            error_message: self.error_message,
            resource_ids: self.resource_ids,
        }
    }
}
