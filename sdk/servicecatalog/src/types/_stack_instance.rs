// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An CloudFormation stack, in a specific account and Region, that's part of a stack set operation. A stack instance is a reference to an attempted or actual stack in a given account within a given Region. A stack instance can exist without a stack—for example, if the stack couldn't be created for some reason. A stack instance is associated with only one stack set. Each stack instance contains the ID of its associated stack set, as well as the ID of the actual stack and the stack status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StackInstance {
    /// <p>The name of the Amazon Web Services account that the stack instance is associated with.</p>
    pub account: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Amazon Web Services Region that the stack instance is associated with.</p>
    pub region: ::std::option::Option<::std::string::String>,
    /// <p>The status of the stack instance, in terms of its synchronization with its associated stack set.</p>
    /// <ul>
    /// <li>
    /// <p><code>INOPERABLE</code>: A <code>DeleteStackInstances</code> operation has failed and left the stack in an unstable state. Stacks in this state are excluded from further <code>UpdateStackSet</code> operations. You might need to perform a <code>DeleteStackInstances</code> operation, with <code>RetainStacks</code> set to true, to delete the stack instance, and then delete the stack manually.</p></li>
    /// <li>
    /// <p><code>OUTDATED</code>: The stack isn't currently up to date with the stack set because either the associated stack failed during a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation, or the stack was part of a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation that failed or was stopped before the stack was created or updated.</p></li>
    /// <li>
    /// <p><code>CURRENT</code>: The stack is currently up to date with the stack set.</p></li>
    /// </ul>
    pub stack_instance_status: ::std::option::Option<crate::types::StackInstanceStatus>,
}
impl StackInstance {
    /// <p>The name of the Amazon Web Services account that the stack instance is associated with.</p>
    pub fn account(&self) -> ::std::option::Option<&str> {
        self.account.as_deref()
    }
    /// <p>The name of the Amazon Web Services Region that the stack instance is associated with.</p>
    pub fn region(&self) -> ::std::option::Option<&str> {
        self.region.as_deref()
    }
    /// <p>The status of the stack instance, in terms of its synchronization with its associated stack set.</p>
    /// <ul>
    /// <li>
    /// <p><code>INOPERABLE</code>: A <code>DeleteStackInstances</code> operation has failed and left the stack in an unstable state. Stacks in this state are excluded from further <code>UpdateStackSet</code> operations. You might need to perform a <code>DeleteStackInstances</code> operation, with <code>RetainStacks</code> set to true, to delete the stack instance, and then delete the stack manually.</p></li>
    /// <li>
    /// <p><code>OUTDATED</code>: The stack isn't currently up to date with the stack set because either the associated stack failed during a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation, or the stack was part of a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation that failed or was stopped before the stack was created or updated.</p></li>
    /// <li>
    /// <p><code>CURRENT</code>: The stack is currently up to date with the stack set.</p></li>
    /// </ul>
    pub fn stack_instance_status(&self) -> ::std::option::Option<&crate::types::StackInstanceStatus> {
        self.stack_instance_status.as_ref()
    }
}
impl StackInstance {
    /// Creates a new builder-style object to manufacture [`StackInstance`](crate::types::StackInstance).
    pub fn builder() -> crate::types::builders::StackInstanceBuilder {
        crate::types::builders::StackInstanceBuilder::default()
    }
}

/// A builder for [`StackInstance`](crate::types::StackInstance).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StackInstanceBuilder {
    pub(crate) account: ::std::option::Option<::std::string::String>,
    pub(crate) region: ::std::option::Option<::std::string::String>,
    pub(crate) stack_instance_status: ::std::option::Option<crate::types::StackInstanceStatus>,
}
impl StackInstanceBuilder {
    /// <p>The name of the Amazon Web Services account that the stack instance is associated with.</p>
    pub fn account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon Web Services account that the stack instance is associated with.</p>
    pub fn set_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account = input;
        self
    }
    /// <p>The name of the Amazon Web Services account that the stack instance is associated with.</p>
    pub fn get_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.account
    }
    /// <p>The name of the Amazon Web Services Region that the stack instance is associated with.</p>
    pub fn region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon Web Services Region that the stack instance is associated with.</p>
    pub fn set_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.region = input;
        self
    }
    /// <p>The name of the Amazon Web Services Region that the stack instance is associated with.</p>
    pub fn get_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.region
    }
    /// <p>The status of the stack instance, in terms of its synchronization with its associated stack set.</p>
    /// <ul>
    /// <li>
    /// <p><code>INOPERABLE</code>: A <code>DeleteStackInstances</code> operation has failed and left the stack in an unstable state. Stacks in this state are excluded from further <code>UpdateStackSet</code> operations. You might need to perform a <code>DeleteStackInstances</code> operation, with <code>RetainStacks</code> set to true, to delete the stack instance, and then delete the stack manually.</p></li>
    /// <li>
    /// <p><code>OUTDATED</code>: The stack isn't currently up to date with the stack set because either the associated stack failed during a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation, or the stack was part of a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation that failed or was stopped before the stack was created or updated.</p></li>
    /// <li>
    /// <p><code>CURRENT</code>: The stack is currently up to date with the stack set.</p></li>
    /// </ul>
    pub fn stack_instance_status(mut self, input: crate::types::StackInstanceStatus) -> Self {
        self.stack_instance_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the stack instance, in terms of its synchronization with its associated stack set.</p>
    /// <ul>
    /// <li>
    /// <p><code>INOPERABLE</code>: A <code>DeleteStackInstances</code> operation has failed and left the stack in an unstable state. Stacks in this state are excluded from further <code>UpdateStackSet</code> operations. You might need to perform a <code>DeleteStackInstances</code> operation, with <code>RetainStacks</code> set to true, to delete the stack instance, and then delete the stack manually.</p></li>
    /// <li>
    /// <p><code>OUTDATED</code>: The stack isn't currently up to date with the stack set because either the associated stack failed during a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation, or the stack was part of a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation that failed or was stopped before the stack was created or updated.</p></li>
    /// <li>
    /// <p><code>CURRENT</code>: The stack is currently up to date with the stack set.</p></li>
    /// </ul>
    pub fn set_stack_instance_status(mut self, input: ::std::option::Option<crate::types::StackInstanceStatus>) -> Self {
        self.stack_instance_status = input;
        self
    }
    /// <p>The status of the stack instance, in terms of its synchronization with its associated stack set.</p>
    /// <ul>
    /// <li>
    /// <p><code>INOPERABLE</code>: A <code>DeleteStackInstances</code> operation has failed and left the stack in an unstable state. Stacks in this state are excluded from further <code>UpdateStackSet</code> operations. You might need to perform a <code>DeleteStackInstances</code> operation, with <code>RetainStacks</code> set to true, to delete the stack instance, and then delete the stack manually.</p></li>
    /// <li>
    /// <p><code>OUTDATED</code>: The stack isn't currently up to date with the stack set because either the associated stack failed during a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation, or the stack was part of a <code>CreateStackSet</code> or <code>UpdateStackSet</code> operation that failed or was stopped before the stack was created or updated.</p></li>
    /// <li>
    /// <p><code>CURRENT</code>: The stack is currently up to date with the stack set.</p></li>
    /// </ul>
    pub fn get_stack_instance_status(&self) -> &::std::option::Option<crate::types::StackInstanceStatus> {
        &self.stack_instance_status
    }
    /// Consumes the builder and constructs a [`StackInstance`](crate::types::StackInstance).
    pub fn build(self) -> crate::types::StackInstance {
        crate::types::StackInstance {
            account: self.account,
            region: self.region,
            stack_instance_status: self.stack_instance_status,
        }
    }
}
