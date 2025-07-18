// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A structure that is used to provide the status of the provisioning operation for a specified permission set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PermissionSetProvisioningStatus {
    /// <p>The status of the permission set provisioning process.</p>
    pub status: ::std::option::Option<crate::types::StatusValues>,
    /// <p>The identifier for tracking the request operation that is generated by the universally unique identifier (UUID) workflow.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the Amazon Web Services account from which to list the assignments.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the permission set that is being provisioned. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub permission_set_arn: ::std::option::Option<::std::string::String>,
    /// <p>The message that contains an error or exception in case of an operation failure.</p>
    pub failure_reason: ::std::option::Option<::std::string::String>,
    /// <p>The date that the permission set was created.</p>
    pub created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl PermissionSetProvisioningStatus {
    /// <p>The status of the permission set provisioning process.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::StatusValues> {
        self.status.as_ref()
    }
    /// <p>The identifier for tracking the request operation that is generated by the universally unique identifier (UUID) workflow.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The identifier of the Amazon Web Services account from which to list the assignments.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The ARN of the permission set that is being provisioned. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn permission_set_arn(&self) -> ::std::option::Option<&str> {
        self.permission_set_arn.as_deref()
    }
    /// <p>The message that contains an error or exception in case of an operation failure.</p>
    pub fn failure_reason(&self) -> ::std::option::Option<&str> {
        self.failure_reason.as_deref()
    }
    /// <p>The date that the permission set was created.</p>
    pub fn created_date(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_date.as_ref()
    }
}
impl PermissionSetProvisioningStatus {
    /// Creates a new builder-style object to manufacture [`PermissionSetProvisioningStatus`](crate::types::PermissionSetProvisioningStatus).
    pub fn builder() -> crate::types::builders::PermissionSetProvisioningStatusBuilder {
        crate::types::builders::PermissionSetProvisioningStatusBuilder::default()
    }
}

/// A builder for [`PermissionSetProvisioningStatus`](crate::types::PermissionSetProvisioningStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PermissionSetProvisioningStatusBuilder {
    pub(crate) status: ::std::option::Option<crate::types::StatusValues>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) permission_set_arn: ::std::option::Option<::std::string::String>,
    pub(crate) failure_reason: ::std::option::Option<::std::string::String>,
    pub(crate) created_date: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl PermissionSetProvisioningStatusBuilder {
    /// <p>The status of the permission set provisioning process.</p>
    pub fn status(mut self, input: crate::types::StatusValues) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the permission set provisioning process.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::StatusValues>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the permission set provisioning process.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::StatusValues> {
        &self.status
    }
    /// <p>The identifier for tracking the request operation that is generated by the universally unique identifier (UUID) workflow.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for tracking the request operation that is generated by the universally unique identifier (UUID) workflow.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The identifier for tracking the request operation that is generated by the universally unique identifier (UUID) workflow.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The identifier of the Amazon Web Services account from which to list the assignments.</p>
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Web Services account from which to list the assignments.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The identifier of the Amazon Web Services account from which to list the assignments.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The ARN of the permission set that is being provisioned. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn permission_set_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.permission_set_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the permission set that is being provisioned. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn set_permission_set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.permission_set_arn = input;
        self
    }
    /// <p>The ARN of the permission set that is being provisioned. For more information about ARNs, see <a href="/general/latest/gr/aws-arns-and-namespaces.html">Amazon Resource Names (ARNs) and Amazon Web Services Service Namespaces</a> in the <i>Amazon Web Services General Reference</i>.</p>
    pub fn get_permission_set_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.permission_set_arn
    }
    /// <p>The message that contains an error or exception in case of an operation failure.</p>
    pub fn failure_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.failure_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The message that contains an error or exception in case of an operation failure.</p>
    pub fn set_failure_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.failure_reason = input;
        self
    }
    /// <p>The message that contains an error or exception in case of an operation failure.</p>
    pub fn get_failure_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.failure_reason
    }
    /// <p>The date that the permission set was created.</p>
    pub fn created_date(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_date = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date that the permission set was created.</p>
    pub fn set_created_date(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_date = input;
        self
    }
    /// <p>The date that the permission set was created.</p>
    pub fn get_created_date(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_date
    }
    /// Consumes the builder and constructs a [`PermissionSetProvisioningStatus`](crate::types::PermissionSetProvisioningStatus).
    pub fn build(self) -> crate::types::PermissionSetProvisioningStatus {
        crate::types::PermissionSetProvisioningStatus {
            status: self.status,
            request_id: self.request_id,
            account_id: self.account_id,
            permission_set_arn: self.permission_set_arn,
            failure_reason: self.failure_reason,
            created_date: self.created_date,
        }
    }
}
