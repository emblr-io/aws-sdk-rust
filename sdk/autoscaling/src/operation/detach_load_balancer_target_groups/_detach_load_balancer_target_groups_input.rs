// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetachLoadBalancerTargetGroupsInput {
    /// <p>The name of the Auto Scaling group.</p>
    pub auto_scaling_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Names (ARN) of the target groups. You can specify up to 10 target groups.</p>
    pub target_group_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DetachLoadBalancerTargetGroupsInput {
    /// <p>The name of the Auto Scaling group.</p>
    pub fn auto_scaling_group_name(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_group_name.as_deref()
    }
    /// <p>The Amazon Resource Names (ARN) of the target groups. You can specify up to 10 target groups.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.target_group_arns.is_none()`.
    pub fn target_group_arns(&self) -> &[::std::string::String] {
        self.target_group_arns.as_deref().unwrap_or_default()
    }
}
impl DetachLoadBalancerTargetGroupsInput {
    /// Creates a new builder-style object to manufacture [`DetachLoadBalancerTargetGroupsInput`](crate::operation::detach_load_balancer_target_groups::DetachLoadBalancerTargetGroupsInput).
    pub fn builder() -> crate::operation::detach_load_balancer_target_groups::builders::DetachLoadBalancerTargetGroupsInputBuilder {
        crate::operation::detach_load_balancer_target_groups::builders::DetachLoadBalancerTargetGroupsInputBuilder::default()
    }
}

/// A builder for [`DetachLoadBalancerTargetGroupsInput`](crate::operation::detach_load_balancer_target_groups::DetachLoadBalancerTargetGroupsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetachLoadBalancerTargetGroupsInputBuilder {
    pub(crate) auto_scaling_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) target_group_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DetachLoadBalancerTargetGroupsInputBuilder {
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
    /// Appends an item to `target_group_arns`.
    ///
    /// To override the contents of this collection use [`set_target_group_arns`](Self::set_target_group_arns).
    ///
    /// <p>The Amazon Resource Names (ARN) of the target groups. You can specify up to 10 target groups.</p>
    pub fn target_group_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.target_group_arns.unwrap_or_default();
        v.push(input.into());
        self.target_group_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Resource Names (ARN) of the target groups. You can specify up to 10 target groups.</p>
    pub fn set_target_group_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.target_group_arns = input;
        self
    }
    /// <p>The Amazon Resource Names (ARN) of the target groups. You can specify up to 10 target groups.</p>
    pub fn get_target_group_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.target_group_arns
    }
    /// Consumes the builder and constructs a [`DetachLoadBalancerTargetGroupsInput`](crate::operation::detach_load_balancer_target_groups::DetachLoadBalancerTargetGroupsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::detach_load_balancer_target_groups::DetachLoadBalancerTargetGroupsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::detach_load_balancer_target_groups::DetachLoadBalancerTargetGroupsInput {
                auto_scaling_group_name: self.auto_scaling_group_name,
                target_group_arns: self.target_group_arns,
            },
        )
    }
}
