// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a provisioned product.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProvisionedProductAttribute {
    /// <p>The user-friendly name of the provisioned product.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the provisioned product.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The type of provisioned product. The supported values are <code>CFN_STACK</code>, <code>CFN_STACKSET</code>, <code>TERRAFORM_OPEN_SOURCE</code>, <code>TERRAFORM_CLOUD</code>, and <code>EXTERNAL</code>.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the provisioned product.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the provisioned product.</p>
    /// <ul>
    /// <li>
    /// <p><code>AVAILABLE</code> - Stable state, ready to perform any operation. The most recent operation succeeded and completed.</p></li>
    /// <li>
    /// <p><code>UNDER_CHANGE</code> - Transitive state. Operations performed might not have valid results. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// <li>
    /// <p><code>TAINTED</code> - Stable state, ready to perform any operation. The stack has completed the requested operation but is not exactly what was requested. For example, a request to update to a new version failed and the stack rolled back to the current version.</p></li>
    /// <li>
    /// <p><code>ERROR</code> - An unexpected error occurred. The provisioned product exists but the stack is not running. For example, CloudFormation received a parameter value that was not valid and could not launch the stack.</p></li>
    /// <li>
    /// <p><code>PLAN_IN_PROGRESS</code> - Transitive state. The plan operations were performed to provision a new product, but resources have not yet been created. After reviewing the list of resources to be created, execute the plan. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::ProvisionedProductStatus>,
    /// <p>The current status message of the provisioned product.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
    /// <p>The UTC time stamp of the creation time.</p>
    pub created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub idempotency_token: ::std::option::Option<::std::string::String>,
    /// <p>The record identifier of the last request performed on this provisioned product.</p>
    pub last_record_id: ::std::option::Option<::std::string::String>,
    /// <p>The record identifier of the last request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub last_provisioning_record_id: ::std::option::Option<::std::string::String>,
    /// <p>The record identifier of the last successful request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub last_successful_provisioning_record_id: ::std::option::Option<::std::string::String>,
    /// <p>One or more tags.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The assigned identifier for the resource, such as an EC2 instance ID or an S3 bucket name.</p>
    pub physical_id: ::std::option::Option<::std::string::String>,
    /// <p>The product identifier.</p>
    pub product_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the product.</p>
    pub product_name: ::std::option::Option<::std::string::String>,
    /// <p>The identifier of the provisioning artifact.</p>
    pub provisioning_artifact_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the provisioning artifact.</p>
    pub provisioning_artifact_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub user_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the user in the session. This ARN might contain a session ID.</p>
    pub user_arn_session: ::std::option::Option<::std::string::String>,
}
impl ProvisionedProductAttribute {
    /// <p>The user-friendly name of the provisioned product.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The ARN of the provisioned product.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The type of provisioned product. The supported values are <code>CFN_STACK</code>, <code>CFN_STACKSET</code>, <code>TERRAFORM_OPEN_SOURCE</code>, <code>TERRAFORM_CLOUD</code>, and <code>EXTERNAL</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The identifier of the provisioned product.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The current status of the provisioned product.</p>
    /// <ul>
    /// <li>
    /// <p><code>AVAILABLE</code> - Stable state, ready to perform any operation. The most recent operation succeeded and completed.</p></li>
    /// <li>
    /// <p><code>UNDER_CHANGE</code> - Transitive state. Operations performed might not have valid results. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// <li>
    /// <p><code>TAINTED</code> - Stable state, ready to perform any operation. The stack has completed the requested operation but is not exactly what was requested. For example, a request to update to a new version failed and the stack rolled back to the current version.</p></li>
    /// <li>
    /// <p><code>ERROR</code> - An unexpected error occurred. The provisioned product exists but the stack is not running. For example, CloudFormation received a parameter value that was not valid and could not launch the stack.</p></li>
    /// <li>
    /// <p><code>PLAN_IN_PROGRESS</code> - Transitive state. The plan operations were performed to provision a new product, but resources have not yet been created. After reviewing the list of resources to be created, execute the plan. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ProvisionedProductStatus> {
        self.status.as_ref()
    }
    /// <p>The current status message of the provisioned product.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
    /// <p>The UTC time stamp of the creation time.</p>
    pub fn created_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_time.as_ref()
    }
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub fn idempotency_token(&self) -> ::std::option::Option<&str> {
        self.idempotency_token.as_deref()
    }
    /// <p>The record identifier of the last request performed on this provisioned product.</p>
    pub fn last_record_id(&self) -> ::std::option::Option<&str> {
        self.last_record_id.as_deref()
    }
    /// <p>The record identifier of the last request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub fn last_provisioning_record_id(&self) -> ::std::option::Option<&str> {
        self.last_provisioning_record_id.as_deref()
    }
    /// <p>The record identifier of the last successful request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub fn last_successful_provisioning_record_id(&self) -> ::std::option::Option<&str> {
        self.last_successful_provisioning_record_id.as_deref()
    }
    /// <p>One or more tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The assigned identifier for the resource, such as an EC2 instance ID or an S3 bucket name.</p>
    pub fn physical_id(&self) -> ::std::option::Option<&str> {
        self.physical_id.as_deref()
    }
    /// <p>The product identifier.</p>
    pub fn product_id(&self) -> ::std::option::Option<&str> {
        self.product_id.as_deref()
    }
    /// <p>The name of the product.</p>
    pub fn product_name(&self) -> ::std::option::Option<&str> {
        self.product_name.as_deref()
    }
    /// <p>The identifier of the provisioning artifact.</p>
    pub fn provisioning_artifact_id(&self) -> ::std::option::Option<&str> {
        self.provisioning_artifact_id.as_deref()
    }
    /// <p>The name of the provisioning artifact.</p>
    pub fn provisioning_artifact_name(&self) -> ::std::option::Option<&str> {
        self.provisioning_artifact_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub fn user_arn(&self) -> ::std::option::Option<&str> {
        self.user_arn.as_deref()
    }
    /// <p>The ARN of the user in the session. This ARN might contain a session ID.</p>
    pub fn user_arn_session(&self) -> ::std::option::Option<&str> {
        self.user_arn_session.as_deref()
    }
}
impl ProvisionedProductAttribute {
    /// Creates a new builder-style object to manufacture [`ProvisionedProductAttribute`](crate::types::ProvisionedProductAttribute).
    pub fn builder() -> crate::types::builders::ProvisionedProductAttributeBuilder {
        crate::types::builders::ProvisionedProductAttributeBuilder::default()
    }
}

/// A builder for [`ProvisionedProductAttribute`](crate::types::ProvisionedProductAttribute).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProvisionedProductAttributeBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ProvisionedProductStatus>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) idempotency_token: ::std::option::Option<::std::string::String>,
    pub(crate) last_record_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_provisioning_record_id: ::std::option::Option<::std::string::String>,
    pub(crate) last_successful_provisioning_record_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) physical_id: ::std::option::Option<::std::string::String>,
    pub(crate) product_id: ::std::option::Option<::std::string::String>,
    pub(crate) product_name: ::std::option::Option<::std::string::String>,
    pub(crate) provisioning_artifact_id: ::std::option::Option<::std::string::String>,
    pub(crate) provisioning_artifact_name: ::std::option::Option<::std::string::String>,
    pub(crate) user_arn: ::std::option::Option<::std::string::String>,
    pub(crate) user_arn_session: ::std::option::Option<::std::string::String>,
}
impl ProvisionedProductAttributeBuilder {
    /// <p>The user-friendly name of the provisioned product.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-friendly name of the provisioned product.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The user-friendly name of the provisioned product.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The ARN of the provisioned product.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the provisioned product.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the provisioned product.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The type of provisioned product. The supported values are <code>CFN_STACK</code>, <code>CFN_STACKSET</code>, <code>TERRAFORM_OPEN_SOURCE</code>, <code>TERRAFORM_CLOUD</code>, and <code>EXTERNAL</code>.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of provisioned product. The supported values are <code>CFN_STACK</code>, <code>CFN_STACKSET</code>, <code>TERRAFORM_OPEN_SOURCE</code>, <code>TERRAFORM_CLOUD</code>, and <code>EXTERNAL</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of provisioned product. The supported values are <code>CFN_STACK</code>, <code>CFN_STACKSET</code>, <code>TERRAFORM_OPEN_SOURCE</code>, <code>TERRAFORM_CLOUD</code>, and <code>EXTERNAL</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The identifier of the provisioned product.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the provisioned product.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the provisioned product.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The current status of the provisioned product.</p>
    /// <ul>
    /// <li>
    /// <p><code>AVAILABLE</code> - Stable state, ready to perform any operation. The most recent operation succeeded and completed.</p></li>
    /// <li>
    /// <p><code>UNDER_CHANGE</code> - Transitive state. Operations performed might not have valid results. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// <li>
    /// <p><code>TAINTED</code> - Stable state, ready to perform any operation. The stack has completed the requested operation but is not exactly what was requested. For example, a request to update to a new version failed and the stack rolled back to the current version.</p></li>
    /// <li>
    /// <p><code>ERROR</code> - An unexpected error occurred. The provisioned product exists but the stack is not running. For example, CloudFormation received a parameter value that was not valid and could not launch the stack.</p></li>
    /// <li>
    /// <p><code>PLAN_IN_PROGRESS</code> - Transitive state. The plan operations were performed to provision a new product, but resources have not yet been created. After reviewing the list of resources to be created, execute the plan. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::ProvisionedProductStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the provisioned product.</p>
    /// <ul>
    /// <li>
    /// <p><code>AVAILABLE</code> - Stable state, ready to perform any operation. The most recent operation succeeded and completed.</p></li>
    /// <li>
    /// <p><code>UNDER_CHANGE</code> - Transitive state. Operations performed might not have valid results. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// <li>
    /// <p><code>TAINTED</code> - Stable state, ready to perform any operation. The stack has completed the requested operation but is not exactly what was requested. For example, a request to update to a new version failed and the stack rolled back to the current version.</p></li>
    /// <li>
    /// <p><code>ERROR</code> - An unexpected error occurred. The provisioned product exists but the stack is not running. For example, CloudFormation received a parameter value that was not valid and could not launch the stack.</p></li>
    /// <li>
    /// <p><code>PLAN_IN_PROGRESS</code> - Transitive state. The plan operations were performed to provision a new product, but resources have not yet been created. After reviewing the list of resources to be created, execute the plan. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ProvisionedProductStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the provisioned product.</p>
    /// <ul>
    /// <li>
    /// <p><code>AVAILABLE</code> - Stable state, ready to perform any operation. The most recent operation succeeded and completed.</p></li>
    /// <li>
    /// <p><code>UNDER_CHANGE</code> - Transitive state. Operations performed might not have valid results. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// <li>
    /// <p><code>TAINTED</code> - Stable state, ready to perform any operation. The stack has completed the requested operation but is not exactly what was requested. For example, a request to update to a new version failed and the stack rolled back to the current version.</p></li>
    /// <li>
    /// <p><code>ERROR</code> - An unexpected error occurred. The provisioned product exists but the stack is not running. For example, CloudFormation received a parameter value that was not valid and could not launch the stack.</p></li>
    /// <li>
    /// <p><code>PLAN_IN_PROGRESS</code> - Transitive state. The plan operations were performed to provision a new product, but resources have not yet been created. After reviewing the list of resources to be created, execute the plan. Wait for an <code>AVAILABLE</code> status before performing operations.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ProvisionedProductStatus> {
        &self.status
    }
    /// <p>The current status message of the provisioned product.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current status message of the provisioned product.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>The current status message of the provisioned product.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// <p>The UTC time stamp of the creation time.</p>
    pub fn created_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The UTC time stamp of the creation time.</p>
    pub fn set_created_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_time = input;
        self
    }
    /// <p>The UTC time stamp of the creation time.</p>
    pub fn get_created_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_time
    }
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub fn idempotency_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.idempotency_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub fn set_idempotency_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.idempotency_token = input;
        self
    }
    /// <p>A unique identifier that you provide to ensure idempotency. If multiple requests differ only by the idempotency token, the same response is returned for each repeated request.</p>
    pub fn get_idempotency_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.idempotency_token
    }
    /// <p>The record identifier of the last request performed on this provisioned product.</p>
    pub fn last_record_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_record_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The record identifier of the last request performed on this provisioned product.</p>
    pub fn set_last_record_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_record_id = input;
        self
    }
    /// <p>The record identifier of the last request performed on this provisioned product.</p>
    pub fn get_last_record_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_record_id
    }
    /// <p>The record identifier of the last request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub fn last_provisioning_record_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_provisioning_record_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The record identifier of the last request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub fn set_last_provisioning_record_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_provisioning_record_id = input;
        self
    }
    /// <p>The record identifier of the last request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub fn get_last_provisioning_record_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_provisioning_record_id
    }
    /// <p>The record identifier of the last successful request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub fn last_successful_provisioning_record_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_successful_provisioning_record_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The record identifier of the last successful request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub fn set_last_successful_provisioning_record_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_successful_provisioning_record_id = input;
        self
    }
    /// <p>The record identifier of the last successful request performed on this provisioned product of the following types:</p>
    /// <ul>
    /// <li>
    /// <p>ProvisionProduct</p></li>
    /// <li>
    /// <p>UpdateProvisionedProduct</p></li>
    /// <li>
    /// <p>ExecuteProvisionedProductPlan</p></li>
    /// <li>
    /// <p>TerminateProvisionedProduct</p></li>
    /// </ul>
    pub fn get_last_successful_provisioning_record_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_successful_provisioning_record_id
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>One or more tags.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>One or more tags.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>One or more tags.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The assigned identifier for the resource, such as an EC2 instance ID or an S3 bucket name.</p>
    pub fn physical_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.physical_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The assigned identifier for the resource, such as an EC2 instance ID or an S3 bucket name.</p>
    pub fn set_physical_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.physical_id = input;
        self
    }
    /// <p>The assigned identifier for the resource, such as an EC2 instance ID or an S3 bucket name.</p>
    pub fn get_physical_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.physical_id
    }
    /// <p>The product identifier.</p>
    pub fn product_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The product identifier.</p>
    pub fn set_product_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_id = input;
        self
    }
    /// <p>The product identifier.</p>
    pub fn get_product_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_id
    }
    /// <p>The name of the product.</p>
    pub fn product_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.product_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the product.</p>
    pub fn set_product_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.product_name = input;
        self
    }
    /// <p>The name of the product.</p>
    pub fn get_product_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.product_name
    }
    /// <p>The identifier of the provisioning artifact.</p>
    pub fn provisioning_artifact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provisioning_artifact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the provisioning artifact.</p>
    pub fn set_provisioning_artifact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provisioning_artifact_id = input;
        self
    }
    /// <p>The identifier of the provisioning artifact.</p>
    pub fn get_provisioning_artifact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.provisioning_artifact_id
    }
    /// <p>The name of the provisioning artifact.</p>
    pub fn provisioning_artifact_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provisioning_artifact_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the provisioning artifact.</p>
    pub fn set_provisioning_artifact_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provisioning_artifact_name = input;
        self
    }
    /// <p>The name of the provisioning artifact.</p>
    pub fn get_provisioning_artifact_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.provisioning_artifact_name
    }
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub fn user_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub fn set_user_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the user.</p>
    pub fn get_user_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_arn
    }
    /// <p>The ARN of the user in the session. This ARN might contain a session ID.</p>
    pub fn user_arn_session(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.user_arn_session = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the user in the session. This ARN might contain a session ID.</p>
    pub fn set_user_arn_session(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.user_arn_session = input;
        self
    }
    /// <p>The ARN of the user in the session. This ARN might contain a session ID.</p>
    pub fn get_user_arn_session(&self) -> &::std::option::Option<::std::string::String> {
        &self.user_arn_session
    }
    /// Consumes the builder and constructs a [`ProvisionedProductAttribute`](crate::types::ProvisionedProductAttribute).
    pub fn build(self) -> crate::types::ProvisionedProductAttribute {
        crate::types::ProvisionedProductAttribute {
            name: self.name,
            arn: self.arn,
            r#type: self.r#type,
            id: self.id,
            status: self.status,
            status_message: self.status_message,
            created_time: self.created_time,
            idempotency_token: self.idempotency_token,
            last_record_id: self.last_record_id,
            last_provisioning_record_id: self.last_provisioning_record_id,
            last_successful_provisioning_record_id: self.last_successful_provisioning_record_id,
            tags: self.tags,
            physical_id: self.physical_id,
            product_id: self.product_id,
            product_name: self.product_name,
            provisioning_artifact_id: self.provisioning_artifact_id,
            provisioning_artifact_name: self.provisioning_artifact_name,
            user_arn: self.user_arn,
            user_arn_session: self.user_arn_session,
        }
    }
}
