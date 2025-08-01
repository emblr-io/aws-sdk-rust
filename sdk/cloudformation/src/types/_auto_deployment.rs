// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>\[Service-managed permissions\] Describes whether StackSets automatically deploys to Organizations accounts that are added to a target organization or organizational unit (OU).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoDeployment {
    /// <p>If set to <code>true</code>, StackSets automatically deploys additional stack instances to Organizations accounts that are added to a target organization or organizational unit (OU) in the specified Regions. If an account is removed from a target organization or OU, StackSets deletes stack instances from the account in the specified Regions.</p>
    pub enabled: ::std::option::Option<bool>,
    /// <p>If set to <code>true</code>, stack resources are retained when an account is removed from a target organization or OU. If set to <code>false</code>, stack resources are deleted. Specify only if <code>Enabled</code> is set to <code>True</code>.</p>
    pub retain_stacks_on_account_removal: ::std::option::Option<bool>,
}
impl AutoDeployment {
    /// <p>If set to <code>true</code>, StackSets automatically deploys additional stack instances to Organizations accounts that are added to a target organization or organizational unit (OU) in the specified Regions. If an account is removed from a target organization or OU, StackSets deletes stack instances from the account in the specified Regions.</p>
    pub fn enabled(&self) -> ::std::option::Option<bool> {
        self.enabled
    }
    /// <p>If set to <code>true</code>, stack resources are retained when an account is removed from a target organization or OU. If set to <code>false</code>, stack resources are deleted. Specify only if <code>Enabled</code> is set to <code>True</code>.</p>
    pub fn retain_stacks_on_account_removal(&self) -> ::std::option::Option<bool> {
        self.retain_stacks_on_account_removal
    }
}
impl AutoDeployment {
    /// Creates a new builder-style object to manufacture [`AutoDeployment`](crate::types::AutoDeployment).
    pub fn builder() -> crate::types::builders::AutoDeploymentBuilder {
        crate::types::builders::AutoDeploymentBuilder::default()
    }
}

/// A builder for [`AutoDeployment`](crate::types::AutoDeployment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoDeploymentBuilder {
    pub(crate) enabled: ::std::option::Option<bool>,
    pub(crate) retain_stacks_on_account_removal: ::std::option::Option<bool>,
}
impl AutoDeploymentBuilder {
    /// <p>If set to <code>true</code>, StackSets automatically deploys additional stack instances to Organizations accounts that are added to a target organization or organizational unit (OU) in the specified Regions. If an account is removed from a target organization or OU, StackSets deletes stack instances from the account in the specified Regions.</p>
    pub fn enabled(mut self, input: bool) -> Self {
        self.enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to <code>true</code>, StackSets automatically deploys additional stack instances to Organizations accounts that are added to a target organization or organizational unit (OU) in the specified Regions. If an account is removed from a target organization or OU, StackSets deletes stack instances from the account in the specified Regions.</p>
    pub fn set_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enabled = input;
        self
    }
    /// <p>If set to <code>true</code>, StackSets automatically deploys additional stack instances to Organizations accounts that are added to a target organization or organizational unit (OU) in the specified Regions. If an account is removed from a target organization or OU, StackSets deletes stack instances from the account in the specified Regions.</p>
    pub fn get_enabled(&self) -> &::std::option::Option<bool> {
        &self.enabled
    }
    /// <p>If set to <code>true</code>, stack resources are retained when an account is removed from a target organization or OU. If set to <code>false</code>, stack resources are deleted. Specify only if <code>Enabled</code> is set to <code>True</code>.</p>
    pub fn retain_stacks_on_account_removal(mut self, input: bool) -> Self {
        self.retain_stacks_on_account_removal = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to <code>true</code>, stack resources are retained when an account is removed from a target organization or OU. If set to <code>false</code>, stack resources are deleted. Specify only if <code>Enabled</code> is set to <code>True</code>.</p>
    pub fn set_retain_stacks_on_account_removal(mut self, input: ::std::option::Option<bool>) -> Self {
        self.retain_stacks_on_account_removal = input;
        self
    }
    /// <p>If set to <code>true</code>, stack resources are retained when an account is removed from a target organization or OU. If set to <code>false</code>, stack resources are deleted. Specify only if <code>Enabled</code> is set to <code>True</code>.</p>
    pub fn get_retain_stacks_on_account_removal(&self) -> &::std::option::Option<bool> {
        &self.retain_stacks_on_account_removal
    }
    /// Consumes the builder and constructs a [`AutoDeployment`](crate::types::AutoDeployment).
    pub fn build(self) -> crate::types::AutoDeployment {
        crate::types::AutoDeployment {
            enabled: self.enabled,
            retain_stacks_on_account_removal: self.retain_stacks_on_account_removal,
        }
    }
}
