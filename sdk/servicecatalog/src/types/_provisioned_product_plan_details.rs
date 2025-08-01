// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a plan.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProvisionedProductPlanDetails {
    /// <p>The UTC time stamp of the creation time.</p>
    pub created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>.</p>
    pub path_id: ::std::option::Option<::std::string::String>,
    /// <p>The product identifier.</p>
    pub product_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the plan.</p>
    pub plan_name: ::std::option::Option<::std::string::String>,
    /// <p>The plan identifier.</p>
    pub plan_id: ::std::option::Option<::std::string::String>,
    /// <p>The product identifier.</p>
    pub provision_product_id: ::std::option::Option<::std::string::String>,
    /// <p>The user-friendly name of the provisioned product.</p>
    pub provision_product_name: ::std::option::Option<::std::string::String>,
    /// <p>The plan type.</p>
    pub plan_type: ::std::option::Option<crate::types::ProvisionedProductPlanType>,
    /// <p>The identifier of the provisioning artifact.</p>
    pub provisioning_artifact_id: ::std::option::Option<::std::string::String>,
    /// <p>The status.</p>
    pub status: ::std::option::Option<crate::types::ProvisionedProductPlanStatus>,
    /// <p>The UTC time stamp when the plan was last updated.</p>
    pub updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>Passed to CloudFormation. The SNS topic ARNs to which to publish stack-related events.</p>
    pub notification_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Parameters specified by the administrator that are required for provisioning the product.</p>
    pub provisioning_parameters: ::std::option::Option<::std::vec::Vec<crate::types::UpdateProvisioningParameter>>,
    /// <p>One or more tags.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The status message.</p>
    pub status_message: ::std::option::Option<::std::string::String>,
}
impl ProvisionedProductPlanDetails {
    /// <p>The UTC time stamp of the creation time.</p>
    pub fn created_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_time.as_ref()
    }
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>.</p>
    pub fn path_id(&self) -> ::std::option::Option<&str> {
        self.path_id.as_deref()
    }
    /// <p>The product identifier.</p>
    pub fn product_id(&self) -> ::std::option::Option<&str> {
        self.product_id.as_deref()
    }
    /// <p>The name of the plan.</p>
    pub fn plan_name(&self) -> ::std::option::Option<&str> {
        self.plan_name.as_deref()
    }
    /// <p>The plan identifier.</p>
    pub fn plan_id(&self) -> ::std::option::Option<&str> {
        self.plan_id.as_deref()
    }
    /// <p>The product identifier.</p>
    pub fn provision_product_id(&self) -> ::std::option::Option<&str> {
        self.provision_product_id.as_deref()
    }
    /// <p>The user-friendly name of the provisioned product.</p>
    pub fn provision_product_name(&self) -> ::std::option::Option<&str> {
        self.provision_product_name.as_deref()
    }
    /// <p>The plan type.</p>
    pub fn plan_type(&self) -> ::std::option::Option<&crate::types::ProvisionedProductPlanType> {
        self.plan_type.as_ref()
    }
    /// <p>The identifier of the provisioning artifact.</p>
    pub fn provisioning_artifact_id(&self) -> ::std::option::Option<&str> {
        self.provisioning_artifact_id.as_deref()
    }
    /// <p>The status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ProvisionedProductPlanStatus> {
        self.status.as_ref()
    }
    /// <p>The UTC time stamp when the plan was last updated.</p>
    pub fn updated_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_time.as_ref()
    }
    /// <p>Passed to CloudFormation. The SNS topic ARNs to which to publish stack-related events.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.notification_arns.is_none()`.
    pub fn notification_arns(&self) -> &[::std::string::String] {
        self.notification_arns.as_deref().unwrap_or_default()
    }
    /// <p>Parameters specified by the administrator that are required for provisioning the product.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.provisioning_parameters.is_none()`.
    pub fn provisioning_parameters(&self) -> &[crate::types::UpdateProvisioningParameter] {
        self.provisioning_parameters.as_deref().unwrap_or_default()
    }
    /// <p>One or more tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The status message.</p>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
}
impl ProvisionedProductPlanDetails {
    /// Creates a new builder-style object to manufacture [`ProvisionedProductPlanDetails`](crate::types::ProvisionedProductPlanDetails).
    pub fn builder() -> crate::types::builders::ProvisionedProductPlanDetailsBuilder {
        crate::types::builders::ProvisionedProductPlanDetailsBuilder::default()
    }
}

/// A builder for [`ProvisionedProductPlanDetails`](crate::types::ProvisionedProductPlanDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProvisionedProductPlanDetailsBuilder {
    pub(crate) created_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) path_id: ::std::option::Option<::std::string::String>,
    pub(crate) product_id: ::std::option::Option<::std::string::String>,
    pub(crate) plan_name: ::std::option::Option<::std::string::String>,
    pub(crate) plan_id: ::std::option::Option<::std::string::String>,
    pub(crate) provision_product_id: ::std::option::Option<::std::string::String>,
    pub(crate) provision_product_name: ::std::option::Option<::std::string::String>,
    pub(crate) plan_type: ::std::option::Option<crate::types::ProvisionedProductPlanType>,
    pub(crate) provisioning_artifact_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ProvisionedProductPlanStatus>,
    pub(crate) updated_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) notification_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) provisioning_parameters: ::std::option::Option<::std::vec::Vec<crate::types::UpdateProvisioningParameter>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
}
impl ProvisionedProductPlanDetailsBuilder {
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
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>.</p>
    pub fn path_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.path_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>.</p>
    pub fn set_path_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.path_id = input;
        self
    }
    /// <p>The path identifier of the product. This value is optional if the product has a default path, and required if the product has more than one path. To list the paths for a product, use <code>ListLaunchPaths</code>.</p>
    pub fn get_path_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.path_id
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
    /// <p>The name of the plan.</p>
    pub fn plan_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.plan_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the plan.</p>
    pub fn set_plan_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.plan_name = input;
        self
    }
    /// <p>The name of the plan.</p>
    pub fn get_plan_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.plan_name
    }
    /// <p>The plan identifier.</p>
    pub fn plan_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.plan_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The plan identifier.</p>
    pub fn set_plan_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.plan_id = input;
        self
    }
    /// <p>The plan identifier.</p>
    pub fn get_plan_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.plan_id
    }
    /// <p>The product identifier.</p>
    pub fn provision_product_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provision_product_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The product identifier.</p>
    pub fn set_provision_product_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provision_product_id = input;
        self
    }
    /// <p>The product identifier.</p>
    pub fn get_provision_product_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.provision_product_id
    }
    /// <p>The user-friendly name of the provisioned product.</p>
    pub fn provision_product_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provision_product_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The user-friendly name of the provisioned product.</p>
    pub fn set_provision_product_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provision_product_name = input;
        self
    }
    /// <p>The user-friendly name of the provisioned product.</p>
    pub fn get_provision_product_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.provision_product_name
    }
    /// <p>The plan type.</p>
    pub fn plan_type(mut self, input: crate::types::ProvisionedProductPlanType) -> Self {
        self.plan_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The plan type.</p>
    pub fn set_plan_type(mut self, input: ::std::option::Option<crate::types::ProvisionedProductPlanType>) -> Self {
        self.plan_type = input;
        self
    }
    /// <p>The plan type.</p>
    pub fn get_plan_type(&self) -> &::std::option::Option<crate::types::ProvisionedProductPlanType> {
        &self.plan_type
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
    /// <p>The status.</p>
    pub fn status(mut self, input: crate::types::ProvisionedProductPlanStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ProvisionedProductPlanStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ProvisionedProductPlanStatus> {
        &self.status
    }
    /// <p>The UTC time stamp when the plan was last updated.</p>
    pub fn updated_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The UTC time stamp when the plan was last updated.</p>
    pub fn set_updated_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_time = input;
        self
    }
    /// <p>The UTC time stamp when the plan was last updated.</p>
    pub fn get_updated_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_time
    }
    /// Appends an item to `notification_arns`.
    ///
    /// To override the contents of this collection use [`set_notification_arns`](Self::set_notification_arns).
    ///
    /// <p>Passed to CloudFormation. The SNS topic ARNs to which to publish stack-related events.</p>
    pub fn notification_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.notification_arns.unwrap_or_default();
        v.push(input.into());
        self.notification_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>Passed to CloudFormation. The SNS topic ARNs to which to publish stack-related events.</p>
    pub fn set_notification_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.notification_arns = input;
        self
    }
    /// <p>Passed to CloudFormation. The SNS topic ARNs to which to publish stack-related events.</p>
    pub fn get_notification_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.notification_arns
    }
    /// Appends an item to `provisioning_parameters`.
    ///
    /// To override the contents of this collection use [`set_provisioning_parameters`](Self::set_provisioning_parameters).
    ///
    /// <p>Parameters specified by the administrator that are required for provisioning the product.</p>
    pub fn provisioning_parameters(mut self, input: crate::types::UpdateProvisioningParameter) -> Self {
        let mut v = self.provisioning_parameters.unwrap_or_default();
        v.push(input);
        self.provisioning_parameters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Parameters specified by the administrator that are required for provisioning the product.</p>
    pub fn set_provisioning_parameters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UpdateProvisioningParameter>>) -> Self {
        self.provisioning_parameters = input;
        self
    }
    /// <p>Parameters specified by the administrator that are required for provisioning the product.</p>
    pub fn get_provisioning_parameters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UpdateProvisioningParameter>> {
        &self.provisioning_parameters
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
    /// <p>The status message.</p>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status message.</p>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>The status message.</p>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// Consumes the builder and constructs a [`ProvisionedProductPlanDetails`](crate::types::ProvisionedProductPlanDetails).
    pub fn build(self) -> crate::types::ProvisionedProductPlanDetails {
        crate::types::ProvisionedProductPlanDetails {
            created_time: self.created_time,
            path_id: self.path_id,
            product_id: self.product_id,
            plan_name: self.plan_name,
            plan_id: self.plan_id,
            provision_product_id: self.provision_product_id,
            provision_product_name: self.provision_product_name,
            plan_type: self.plan_type,
            provisioning_artifact_id: self.provisioning_artifact_id,
            status: self.status,
            updated_time: self.updated_time,
            notification_arns: self.notification_arns,
            provisioning_parameters: self.provisioning_parameters,
            tags: self.tags,
            status_message: self.status_message,
        }
    }
}
