// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>DeleteDeploymentGroup</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteDeploymentGroupOutput {
    /// <p>If the output contains no data, and the corresponding deployment group contained at least one Auto Scaling group, CodeDeploy successfully removed all corresponding Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group. If the output contains data, CodeDeploy could not remove some Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group.</p>
    pub hooks_not_cleaned_up: ::std::option::Option<::std::vec::Vec<crate::types::AutoScalingGroup>>,
    _request_id: Option<String>,
}
impl DeleteDeploymentGroupOutput {
    /// <p>If the output contains no data, and the corresponding deployment group contained at least one Auto Scaling group, CodeDeploy successfully removed all corresponding Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group. If the output contains data, CodeDeploy could not remove some Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.hooks_not_cleaned_up.is_none()`.
    pub fn hooks_not_cleaned_up(&self) -> &[crate::types::AutoScalingGroup] {
        self.hooks_not_cleaned_up.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DeleteDeploymentGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteDeploymentGroupOutput {
    /// Creates a new builder-style object to manufacture [`DeleteDeploymentGroupOutput`](crate::operation::delete_deployment_group::DeleteDeploymentGroupOutput).
    pub fn builder() -> crate::operation::delete_deployment_group::builders::DeleteDeploymentGroupOutputBuilder {
        crate::operation::delete_deployment_group::builders::DeleteDeploymentGroupOutputBuilder::default()
    }
}

/// A builder for [`DeleteDeploymentGroupOutput`](crate::operation::delete_deployment_group::DeleteDeploymentGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteDeploymentGroupOutputBuilder {
    pub(crate) hooks_not_cleaned_up: ::std::option::Option<::std::vec::Vec<crate::types::AutoScalingGroup>>,
    _request_id: Option<String>,
}
impl DeleteDeploymentGroupOutputBuilder {
    /// Appends an item to `hooks_not_cleaned_up`.
    ///
    /// To override the contents of this collection use [`set_hooks_not_cleaned_up`](Self::set_hooks_not_cleaned_up).
    ///
    /// <p>If the output contains no data, and the corresponding deployment group contained at least one Auto Scaling group, CodeDeploy successfully removed all corresponding Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group. If the output contains data, CodeDeploy could not remove some Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group.</p>
    pub fn hooks_not_cleaned_up(mut self, input: crate::types::AutoScalingGroup) -> Self {
        let mut v = self.hooks_not_cleaned_up.unwrap_or_default();
        v.push(input);
        self.hooks_not_cleaned_up = ::std::option::Option::Some(v);
        self
    }
    /// <p>If the output contains no data, and the corresponding deployment group contained at least one Auto Scaling group, CodeDeploy successfully removed all corresponding Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group. If the output contains data, CodeDeploy could not remove some Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group.</p>
    pub fn set_hooks_not_cleaned_up(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::AutoScalingGroup>>) -> Self {
        self.hooks_not_cleaned_up = input;
        self
    }
    /// <p>If the output contains no data, and the corresponding deployment group contained at least one Auto Scaling group, CodeDeploy successfully removed all corresponding Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group. If the output contains data, CodeDeploy could not remove some Auto Scaling lifecycle event hooks from the Amazon EC2 instances in the Auto Scaling group.</p>
    pub fn get_hooks_not_cleaned_up(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AutoScalingGroup>> {
        &self.hooks_not_cleaned_up
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteDeploymentGroupOutput`](crate::operation::delete_deployment_group::DeleteDeploymentGroupOutput).
    pub fn build(self) -> crate::operation::delete_deployment_group::DeleteDeploymentGroupOutput {
        crate::operation::delete_deployment_group::DeleteDeploymentGroupOutput {
            hooks_not_cleaned_up: self.hooks_not_cleaned_up,
            _request_id: self._request_id,
        }
    }
}
