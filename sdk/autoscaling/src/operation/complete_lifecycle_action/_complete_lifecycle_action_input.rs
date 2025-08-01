// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CompleteLifecycleActionInput {
    /// <p>The name of the lifecycle hook.</p>
    pub lifecycle_hook_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the Auto Scaling group.</p>
    pub auto_scaling_group_name: ::std::option::Option<::std::string::String>,
    /// <p>A universally unique identifier (UUID) that identifies a specific lifecycle action associated with an instance. Amazon EC2 Auto Scaling sends this token to the notification target you specified when you created the lifecycle hook.</p>
    pub lifecycle_action_token: ::std::option::Option<::std::string::String>,
    /// <p>The action for the group to take. You can specify either <code>CONTINUE</code> or <code>ABANDON</code>.</p>
    pub lifecycle_action_result: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
}
impl CompleteLifecycleActionInput {
    /// <p>The name of the lifecycle hook.</p>
    pub fn lifecycle_hook_name(&self) -> ::std::option::Option<&str> {
        self.lifecycle_hook_name.as_deref()
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn auto_scaling_group_name(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_group_name.as_deref()
    }
    /// <p>A universally unique identifier (UUID) that identifies a specific lifecycle action associated with an instance. Amazon EC2 Auto Scaling sends this token to the notification target you specified when you created the lifecycle hook.</p>
    pub fn lifecycle_action_token(&self) -> ::std::option::Option<&str> {
        self.lifecycle_action_token.as_deref()
    }
    /// <p>The action for the group to take. You can specify either <code>CONTINUE</code> or <code>ABANDON</code>.</p>
    pub fn lifecycle_action_result(&self) -> ::std::option::Option<&str> {
        self.lifecycle_action_result.as_deref()
    }
    /// <p>The ID of the instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
}
impl CompleteLifecycleActionInput {
    /// Creates a new builder-style object to manufacture [`CompleteLifecycleActionInput`](crate::operation::complete_lifecycle_action::CompleteLifecycleActionInput).
    pub fn builder() -> crate::operation::complete_lifecycle_action::builders::CompleteLifecycleActionInputBuilder {
        crate::operation::complete_lifecycle_action::builders::CompleteLifecycleActionInputBuilder::default()
    }
}

/// A builder for [`CompleteLifecycleActionInput`](crate::operation::complete_lifecycle_action::CompleteLifecycleActionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CompleteLifecycleActionInputBuilder {
    pub(crate) lifecycle_hook_name: ::std::option::Option<::std::string::String>,
    pub(crate) auto_scaling_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_action_token: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_action_result: ::std::option::Option<::std::string::String>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
}
impl CompleteLifecycleActionInputBuilder {
    /// <p>The name of the lifecycle hook.</p>
    /// This field is required.
    pub fn lifecycle_hook_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_hook_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the lifecycle hook.</p>
    pub fn set_lifecycle_hook_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_hook_name = input;
        self
    }
    /// <p>The name of the lifecycle hook.</p>
    pub fn get_lifecycle_hook_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_hook_name
    }
    /// <p>The name of the Auto Scaling group.</p>
    /// This field is required.
    pub fn auto_scaling_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_scaling_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn set_auto_scaling_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_scaling_group_name = input;
        self
    }
    /// <p>The name of the Auto Scaling group.</p>
    pub fn get_auto_scaling_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_scaling_group_name
    }
    /// <p>A universally unique identifier (UUID) that identifies a specific lifecycle action associated with an instance. Amazon EC2 Auto Scaling sends this token to the notification target you specified when you created the lifecycle hook.</p>
    pub fn lifecycle_action_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_action_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A universally unique identifier (UUID) that identifies a specific lifecycle action associated with an instance. Amazon EC2 Auto Scaling sends this token to the notification target you specified when you created the lifecycle hook.</p>
    pub fn set_lifecycle_action_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_action_token = input;
        self
    }
    /// <p>A universally unique identifier (UUID) that identifies a specific lifecycle action associated with an instance. Amazon EC2 Auto Scaling sends this token to the notification target you specified when you created the lifecycle hook.</p>
    pub fn get_lifecycle_action_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_action_token
    }
    /// <p>The action for the group to take. You can specify either <code>CONTINUE</code> or <code>ABANDON</code>.</p>
    /// This field is required.
    pub fn lifecycle_action_result(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_action_result = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The action for the group to take. You can specify either <code>CONTINUE</code> or <code>ABANDON</code>.</p>
    pub fn set_lifecycle_action_result(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_action_result = input;
        self
    }
    /// <p>The action for the group to take. You can specify either <code>CONTINUE</code> or <code>ABANDON</code>.</p>
    pub fn get_lifecycle_action_result(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_action_result
    }
    /// <p>The ID of the instance.</p>
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// Consumes the builder and constructs a [`CompleteLifecycleActionInput`](crate::operation::complete_lifecycle_action::CompleteLifecycleActionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::complete_lifecycle_action::CompleteLifecycleActionInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::complete_lifecycle_action::CompleteLifecycleActionInput {
            lifecycle_hook_name: self.lifecycle_hook_name,
            auto_scaling_group_name: self.auto_scaling_group_name,
            lifecycle_action_token: self.lifecycle_action_token,
            lifecycle_action_result: self.lifecycle_action_result,
            instance_id: self.instance_id,
        })
    }
}
