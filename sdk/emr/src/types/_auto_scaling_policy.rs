// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An automatic scaling policy for a core instance group or task instance group in an Amazon EMR cluster. An automatic scaling policy defines how an instance group dynamically adds and terminates Amazon EC2 instances in response to the value of a CloudWatch metric. See <code>PutAutoScalingPolicy</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AutoScalingPolicy {
    /// <p>The upper and lower Amazon EC2 instance limits for an automatic scaling policy. Automatic scaling activity will not cause an instance group to grow above or below these limits.</p>
    pub constraints: ::std::option::Option<crate::types::ScalingConstraints>,
    /// <p>The scale-in and scale-out rules that comprise the automatic scaling policy.</p>
    pub rules: ::std::option::Option<::std::vec::Vec<crate::types::ScalingRule>>,
}
impl AutoScalingPolicy {
    /// <p>The upper and lower Amazon EC2 instance limits for an automatic scaling policy. Automatic scaling activity will not cause an instance group to grow above or below these limits.</p>
    pub fn constraints(&self) -> ::std::option::Option<&crate::types::ScalingConstraints> {
        self.constraints.as_ref()
    }
    /// <p>The scale-in and scale-out rules that comprise the automatic scaling policy.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rules.is_none()`.
    pub fn rules(&self) -> &[crate::types::ScalingRule] {
        self.rules.as_deref().unwrap_or_default()
    }
}
impl AutoScalingPolicy {
    /// Creates a new builder-style object to manufacture [`AutoScalingPolicy`](crate::types::AutoScalingPolicy).
    pub fn builder() -> crate::types::builders::AutoScalingPolicyBuilder {
        crate::types::builders::AutoScalingPolicyBuilder::default()
    }
}

/// A builder for [`AutoScalingPolicy`](crate::types::AutoScalingPolicy).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AutoScalingPolicyBuilder {
    pub(crate) constraints: ::std::option::Option<crate::types::ScalingConstraints>,
    pub(crate) rules: ::std::option::Option<::std::vec::Vec<crate::types::ScalingRule>>,
}
impl AutoScalingPolicyBuilder {
    /// <p>The upper and lower Amazon EC2 instance limits for an automatic scaling policy. Automatic scaling activity will not cause an instance group to grow above or below these limits.</p>
    /// This field is required.
    pub fn constraints(mut self, input: crate::types::ScalingConstraints) -> Self {
        self.constraints = ::std::option::Option::Some(input);
        self
    }
    /// <p>The upper and lower Amazon EC2 instance limits for an automatic scaling policy. Automatic scaling activity will not cause an instance group to grow above or below these limits.</p>
    pub fn set_constraints(mut self, input: ::std::option::Option<crate::types::ScalingConstraints>) -> Self {
        self.constraints = input;
        self
    }
    /// <p>The upper and lower Amazon EC2 instance limits for an automatic scaling policy. Automatic scaling activity will not cause an instance group to grow above or below these limits.</p>
    pub fn get_constraints(&self) -> &::std::option::Option<crate::types::ScalingConstraints> {
        &self.constraints
    }
    /// Appends an item to `rules`.
    ///
    /// To override the contents of this collection use [`set_rules`](Self::set_rules).
    ///
    /// <p>The scale-in and scale-out rules that comprise the automatic scaling policy.</p>
    pub fn rules(mut self, input: crate::types::ScalingRule) -> Self {
        let mut v = self.rules.unwrap_or_default();
        v.push(input);
        self.rules = ::std::option::Option::Some(v);
        self
    }
    /// <p>The scale-in and scale-out rules that comprise the automatic scaling policy.</p>
    pub fn set_rules(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ScalingRule>>) -> Self {
        self.rules = input;
        self
    }
    /// <p>The scale-in and scale-out rules that comprise the automatic scaling policy.</p>
    pub fn get_rules(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ScalingRule>> {
        &self.rules
    }
    /// Consumes the builder and constructs a [`AutoScalingPolicy`](crate::types::AutoScalingPolicy).
    pub fn build(self) -> crate::types::AutoScalingPolicy {
        crate::types::AutoScalingPolicy {
            constraints: self.constraints,
            rules: self.rules,
        }
    }
}
