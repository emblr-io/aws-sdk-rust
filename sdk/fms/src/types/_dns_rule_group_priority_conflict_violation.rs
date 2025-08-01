// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A rule group that Firewall Manager tried to associate with a VPC has the same priority as a rule group that's already associated.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DnsRuleGroupPriorityConflictViolation {
    /// <p>Information about the VPC ID.</p>
    pub violation_target: ::std::option::Option<::std::string::String>,
    /// <p>A description of the violation that specifies the VPC and the rule group that's already associated with it.</p>
    pub violation_target_description: ::std::option::Option<::std::string::String>,
    /// <p>The priority setting of the two conflicting rule groups.</p>
    pub conflicting_priority: i32,
    /// <p>The ID of the Firewall Manager DNS Firewall policy that was already applied to the VPC. This policy contains the rule group that's already associated with the VPC.</p>
    pub conflicting_policy_id: ::std::option::Option<::std::string::String>,
    /// <p>The priorities of rule groups that are already associated with the VPC. To retry your operation, choose priority settings that aren't in this list for the rule groups in your new DNS Firewall policy.</p>
    pub unavailable_priorities: ::std::option::Option<::std::vec::Vec<i32>>,
}
impl DnsRuleGroupPriorityConflictViolation {
    /// <p>Information about the VPC ID.</p>
    pub fn violation_target(&self) -> ::std::option::Option<&str> {
        self.violation_target.as_deref()
    }
    /// <p>A description of the violation that specifies the VPC and the rule group that's already associated with it.</p>
    pub fn violation_target_description(&self) -> ::std::option::Option<&str> {
        self.violation_target_description.as_deref()
    }
    /// <p>The priority setting of the two conflicting rule groups.</p>
    pub fn conflicting_priority(&self) -> i32 {
        self.conflicting_priority
    }
    /// <p>The ID of the Firewall Manager DNS Firewall policy that was already applied to the VPC. This policy contains the rule group that's already associated with the VPC.</p>
    pub fn conflicting_policy_id(&self) -> ::std::option::Option<&str> {
        self.conflicting_policy_id.as_deref()
    }
    /// <p>The priorities of rule groups that are already associated with the VPC. To retry your operation, choose priority settings that aren't in this list for the rule groups in your new DNS Firewall policy.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.unavailable_priorities.is_none()`.
    pub fn unavailable_priorities(&self) -> &[i32] {
        self.unavailable_priorities.as_deref().unwrap_or_default()
    }
}
impl DnsRuleGroupPriorityConflictViolation {
    /// Creates a new builder-style object to manufacture [`DnsRuleGroupPriorityConflictViolation`](crate::types::DnsRuleGroupPriorityConflictViolation).
    pub fn builder() -> crate::types::builders::DnsRuleGroupPriorityConflictViolationBuilder {
        crate::types::builders::DnsRuleGroupPriorityConflictViolationBuilder::default()
    }
}

/// A builder for [`DnsRuleGroupPriorityConflictViolation`](crate::types::DnsRuleGroupPriorityConflictViolation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DnsRuleGroupPriorityConflictViolationBuilder {
    pub(crate) violation_target: ::std::option::Option<::std::string::String>,
    pub(crate) violation_target_description: ::std::option::Option<::std::string::String>,
    pub(crate) conflicting_priority: ::std::option::Option<i32>,
    pub(crate) conflicting_policy_id: ::std::option::Option<::std::string::String>,
    pub(crate) unavailable_priorities: ::std::option::Option<::std::vec::Vec<i32>>,
}
impl DnsRuleGroupPriorityConflictViolationBuilder {
    /// <p>Information about the VPC ID.</p>
    pub fn violation_target(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.violation_target = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Information about the VPC ID.</p>
    pub fn set_violation_target(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.violation_target = input;
        self
    }
    /// <p>Information about the VPC ID.</p>
    pub fn get_violation_target(&self) -> &::std::option::Option<::std::string::String> {
        &self.violation_target
    }
    /// <p>A description of the violation that specifies the VPC and the rule group that's already associated with it.</p>
    pub fn violation_target_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.violation_target_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the violation that specifies the VPC and the rule group that's already associated with it.</p>
    pub fn set_violation_target_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.violation_target_description = input;
        self
    }
    /// <p>A description of the violation that specifies the VPC and the rule group that's already associated with it.</p>
    pub fn get_violation_target_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.violation_target_description
    }
    /// <p>The priority setting of the two conflicting rule groups.</p>
    pub fn conflicting_priority(mut self, input: i32) -> Self {
        self.conflicting_priority = ::std::option::Option::Some(input);
        self
    }
    /// <p>The priority setting of the two conflicting rule groups.</p>
    pub fn set_conflicting_priority(mut self, input: ::std::option::Option<i32>) -> Self {
        self.conflicting_priority = input;
        self
    }
    /// <p>The priority setting of the two conflicting rule groups.</p>
    pub fn get_conflicting_priority(&self) -> &::std::option::Option<i32> {
        &self.conflicting_priority
    }
    /// <p>The ID of the Firewall Manager DNS Firewall policy that was already applied to the VPC. This policy contains the rule group that's already associated with the VPC.</p>
    pub fn conflicting_policy_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.conflicting_policy_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Firewall Manager DNS Firewall policy that was already applied to the VPC. This policy contains the rule group that's already associated with the VPC.</p>
    pub fn set_conflicting_policy_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.conflicting_policy_id = input;
        self
    }
    /// <p>The ID of the Firewall Manager DNS Firewall policy that was already applied to the VPC. This policy contains the rule group that's already associated with the VPC.</p>
    pub fn get_conflicting_policy_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.conflicting_policy_id
    }
    /// Appends an item to `unavailable_priorities`.
    ///
    /// To override the contents of this collection use [`set_unavailable_priorities`](Self::set_unavailable_priorities).
    ///
    /// <p>The priorities of rule groups that are already associated with the VPC. To retry your operation, choose priority settings that aren't in this list for the rule groups in your new DNS Firewall policy.</p>
    pub fn unavailable_priorities(mut self, input: i32) -> Self {
        let mut v = self.unavailable_priorities.unwrap_or_default();
        v.push(input);
        self.unavailable_priorities = ::std::option::Option::Some(v);
        self
    }
    /// <p>The priorities of rule groups that are already associated with the VPC. To retry your operation, choose priority settings that aren't in this list for the rule groups in your new DNS Firewall policy.</p>
    pub fn set_unavailable_priorities(mut self, input: ::std::option::Option<::std::vec::Vec<i32>>) -> Self {
        self.unavailable_priorities = input;
        self
    }
    /// <p>The priorities of rule groups that are already associated with the VPC. To retry your operation, choose priority settings that aren't in this list for the rule groups in your new DNS Firewall policy.</p>
    pub fn get_unavailable_priorities(&self) -> &::std::option::Option<::std::vec::Vec<i32>> {
        &self.unavailable_priorities
    }
    /// Consumes the builder and constructs a [`DnsRuleGroupPriorityConflictViolation`](crate::types::DnsRuleGroupPriorityConflictViolation).
    pub fn build(self) -> crate::types::DnsRuleGroupPriorityConflictViolation {
        crate::types::DnsRuleGroupPriorityConflictViolation {
            violation_target: self.violation_target,
            violation_target_description: self.violation_target_description,
            conflicting_priority: self.conflicting_priority.unwrap_or_default(),
            conflicting_policy_id: self.conflicting_policy_id,
            unavailable_priorities: self.unavailable_priorities,
        }
    }
}
