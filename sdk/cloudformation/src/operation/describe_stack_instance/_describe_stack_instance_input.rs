// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeStackInstanceInput {
    /// <p>The name or the unique stack ID of the stack set that you want to get stack instance information for.</p>
    pub stack_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of an Amazon Web Services account that's associated with this stack instance.</p>
    pub stack_instance_account: ::std::option::Option<::std::string::String>,
    /// <p>The name of a Region that's associated with this stack instance.</p>
    pub stack_instance_region: ::std::option::Option<::std::string::String>,
    /// <p>\[Service-managed permissions\] Specifies whether you are acting as an account administrator in the organization's management account or as a delegated administrator in a member account.</p>
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>If you are signed in to a delegated administrator account, specify <code>DELEGATED_ADMIN</code>.</p>
    /// <p>Your Amazon Web Services account must be registered as a delegated administrator in the management account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html">Register a delegated administrator</a> in the <i>CloudFormation User Guide</i>.</p></li>
    /// </ul>
    pub call_as: ::std::option::Option<crate::types::CallAs>,
}
impl DescribeStackInstanceInput {
    /// <p>The name or the unique stack ID of the stack set that you want to get stack instance information for.</p>
    pub fn stack_set_name(&self) -> ::std::option::Option<&str> {
        self.stack_set_name.as_deref()
    }
    /// <p>The ID of an Amazon Web Services account that's associated with this stack instance.</p>
    pub fn stack_instance_account(&self) -> ::std::option::Option<&str> {
        self.stack_instance_account.as_deref()
    }
    /// <p>The name of a Region that's associated with this stack instance.</p>
    pub fn stack_instance_region(&self) -> ::std::option::Option<&str> {
        self.stack_instance_region.as_deref()
    }
    /// <p>\[Service-managed permissions\] Specifies whether you are acting as an account administrator in the organization's management account or as a delegated administrator in a member account.</p>
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>If you are signed in to a delegated administrator account, specify <code>DELEGATED_ADMIN</code>.</p>
    /// <p>Your Amazon Web Services account must be registered as a delegated administrator in the management account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html">Register a delegated administrator</a> in the <i>CloudFormation User Guide</i>.</p></li>
    /// </ul>
    pub fn call_as(&self) -> ::std::option::Option<&crate::types::CallAs> {
        self.call_as.as_ref()
    }
}
impl DescribeStackInstanceInput {
    /// Creates a new builder-style object to manufacture [`DescribeStackInstanceInput`](crate::operation::describe_stack_instance::DescribeStackInstanceInput).
    pub fn builder() -> crate::operation::describe_stack_instance::builders::DescribeStackInstanceInputBuilder {
        crate::operation::describe_stack_instance::builders::DescribeStackInstanceInputBuilder::default()
    }
}

/// A builder for [`DescribeStackInstanceInput`](crate::operation::describe_stack_instance::DescribeStackInstanceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeStackInstanceInputBuilder {
    pub(crate) stack_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) stack_instance_account: ::std::option::Option<::std::string::String>,
    pub(crate) stack_instance_region: ::std::option::Option<::std::string::String>,
    pub(crate) call_as: ::std::option::Option<crate::types::CallAs>,
}
impl DescribeStackInstanceInputBuilder {
    /// <p>The name or the unique stack ID of the stack set that you want to get stack instance information for.</p>
    /// This field is required.
    pub fn stack_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name or the unique stack ID of the stack set that you want to get stack instance information for.</p>
    pub fn set_stack_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_set_name = input;
        self
    }
    /// <p>The name or the unique stack ID of the stack set that you want to get stack instance information for.</p>
    pub fn get_stack_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_set_name
    }
    /// <p>The ID of an Amazon Web Services account that's associated with this stack instance.</p>
    /// This field is required.
    pub fn stack_instance_account(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_instance_account = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an Amazon Web Services account that's associated with this stack instance.</p>
    pub fn set_stack_instance_account(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_instance_account = input;
        self
    }
    /// <p>The ID of an Amazon Web Services account that's associated with this stack instance.</p>
    pub fn get_stack_instance_account(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_instance_account
    }
    /// <p>The name of a Region that's associated with this stack instance.</p>
    /// This field is required.
    pub fn stack_instance_region(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_instance_region = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of a Region that's associated with this stack instance.</p>
    pub fn set_stack_instance_region(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_instance_region = input;
        self
    }
    /// <p>The name of a Region that's associated with this stack instance.</p>
    pub fn get_stack_instance_region(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_instance_region
    }
    /// <p>\[Service-managed permissions\] Specifies whether you are acting as an account administrator in the organization's management account or as a delegated administrator in a member account.</p>
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>If you are signed in to a delegated administrator account, specify <code>DELEGATED_ADMIN</code>.</p>
    /// <p>Your Amazon Web Services account must be registered as a delegated administrator in the management account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html">Register a delegated administrator</a> in the <i>CloudFormation User Guide</i>.</p></li>
    /// </ul>
    pub fn call_as(mut self, input: crate::types::CallAs) -> Self {
        self.call_as = ::std::option::Option::Some(input);
        self
    }
    /// <p>\[Service-managed permissions\] Specifies whether you are acting as an account administrator in the organization's management account or as a delegated administrator in a member account.</p>
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>If you are signed in to a delegated administrator account, specify <code>DELEGATED_ADMIN</code>.</p>
    /// <p>Your Amazon Web Services account must be registered as a delegated administrator in the management account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html">Register a delegated administrator</a> in the <i>CloudFormation User Guide</i>.</p></li>
    /// </ul>
    pub fn set_call_as(mut self, input: ::std::option::Option<crate::types::CallAs>) -> Self {
        self.call_as = input;
        self
    }
    /// <p>\[Service-managed permissions\] Specifies whether you are acting as an account administrator in the organization's management account or as a delegated administrator in a member account.</p>
    /// <p>By default, <code>SELF</code> is specified. Use <code>SELF</code> for stack sets with self-managed permissions.</p>
    /// <ul>
    /// <li>
    /// <p>If you are signed in to the management account, specify <code>SELF</code>.</p></li>
    /// <li>
    /// <p>If you are signed in to a delegated administrator account, specify <code>DELEGATED_ADMIN</code>.</p>
    /// <p>Your Amazon Web Services account must be registered as a delegated administrator in the management account. For more information, see <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-orgs-delegated-admin.html">Register a delegated administrator</a> in the <i>CloudFormation User Guide</i>.</p></li>
    /// </ul>
    pub fn get_call_as(&self) -> &::std::option::Option<crate::types::CallAs> {
        &self.call_as
    }
    /// Consumes the builder and constructs a [`DescribeStackInstanceInput`](crate::operation::describe_stack_instance::DescribeStackInstanceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_stack_instance::DescribeStackInstanceInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_stack_instance::DescribeStackInstanceInput {
            stack_set_name: self.stack_set_name,
            stack_instance_account: self.stack_instance_account,
            stack_instance_region: self.stack_instance_region,
            call_as: self.call_as,
        })
    }
}
