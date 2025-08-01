// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A grouping of protected resources that you and Shield Advanced can monitor as a collective. This resource grouping improves the accuracy of detection and reduces false positives.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProtectionGroup {
    /// <p>The name of the protection group. You use this to identify the protection group in lists and to manage the protection group, for example to update, delete, or describe it.</p>
    pub protection_group_id: ::std::string::String,
    /// <p>Defines how Shield combines resource data for the group in order to detect, mitigate, and report events.</p>
    /// <ul>
    /// <li>
    /// <p>Sum - Use the total traffic across the group. This is a good choice for most cases. Examples include Elastic IP addresses for EC2 instances that scale manually or automatically.</p></li>
    /// <li>
    /// <p>Mean - Use the average of the traffic across the group. This is a good choice for resources that share traffic uniformly. Examples include accelerators and load balancers.</p></li>
    /// <li>
    /// <p>Max - Use the highest traffic from each resource. This is useful for resources that don't share traffic and for resources that share that traffic in a non-uniform way. Examples include Amazon CloudFront distributions and origin resources for CloudFront distributions.</p></li>
    /// </ul>
    pub aggregation: crate::types::ProtectionGroupAggregation,
    /// <p>The criteria to use to choose the protected resources for inclusion in the group. You can include all resources that have protections, provide a list of resource ARNs (Amazon Resource Names), or include all resources of a specified resource type.</p>
    pub pattern: crate::types::ProtectionGroupPattern,
    /// <p>The resource type to include in the protection group. All protected resources of this type are included in the protection group. You must set this when you set <code>Pattern</code> to <code>BY_RESOURCE_TYPE</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub resource_type: ::std::option::Option<crate::types::ProtectedResourceType>,
    /// <p>The ARNs (Amazon Resource Names) of the resources to include in the protection group. You must set this when you set <code>Pattern</code> to <code>ARBITRARY</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub members: ::std::vec::Vec<::std::string::String>,
    /// <p>The ARN (Amazon Resource Name) of the protection group.</p>
    pub protection_group_arn: ::std::option::Option<::std::string::String>,
}
impl ProtectionGroup {
    /// <p>The name of the protection group. You use this to identify the protection group in lists and to manage the protection group, for example to update, delete, or describe it.</p>
    pub fn protection_group_id(&self) -> &str {
        use std::ops::Deref;
        self.protection_group_id.deref()
    }
    /// <p>Defines how Shield combines resource data for the group in order to detect, mitigate, and report events.</p>
    /// <ul>
    /// <li>
    /// <p>Sum - Use the total traffic across the group. This is a good choice for most cases. Examples include Elastic IP addresses for EC2 instances that scale manually or automatically.</p></li>
    /// <li>
    /// <p>Mean - Use the average of the traffic across the group. This is a good choice for resources that share traffic uniformly. Examples include accelerators and load balancers.</p></li>
    /// <li>
    /// <p>Max - Use the highest traffic from each resource. This is useful for resources that don't share traffic and for resources that share that traffic in a non-uniform way. Examples include Amazon CloudFront distributions and origin resources for CloudFront distributions.</p></li>
    /// </ul>
    pub fn aggregation(&self) -> &crate::types::ProtectionGroupAggregation {
        &self.aggregation
    }
    /// <p>The criteria to use to choose the protected resources for inclusion in the group. You can include all resources that have protections, provide a list of resource ARNs (Amazon Resource Names), or include all resources of a specified resource type.</p>
    pub fn pattern(&self) -> &crate::types::ProtectionGroupPattern {
        &self.pattern
    }
    /// <p>The resource type to include in the protection group. All protected resources of this type are included in the protection group. You must set this when you set <code>Pattern</code> to <code>BY_RESOURCE_TYPE</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&crate::types::ProtectedResourceType> {
        self.resource_type.as_ref()
    }
    /// <p>The ARNs (Amazon Resource Names) of the resources to include in the protection group. You must set this when you set <code>Pattern</code> to <code>ARBITRARY</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub fn members(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.members.deref()
    }
    /// <p>The ARN (Amazon Resource Name) of the protection group.</p>
    pub fn protection_group_arn(&self) -> ::std::option::Option<&str> {
        self.protection_group_arn.as_deref()
    }
}
impl ProtectionGroup {
    /// Creates a new builder-style object to manufacture [`ProtectionGroup`](crate::types::ProtectionGroup).
    pub fn builder() -> crate::types::builders::ProtectionGroupBuilder {
        crate::types::builders::ProtectionGroupBuilder::default()
    }
}

/// A builder for [`ProtectionGroup`](crate::types::ProtectionGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProtectionGroupBuilder {
    pub(crate) protection_group_id: ::std::option::Option<::std::string::String>,
    pub(crate) aggregation: ::std::option::Option<crate::types::ProtectionGroupAggregation>,
    pub(crate) pattern: ::std::option::Option<crate::types::ProtectionGroupPattern>,
    pub(crate) resource_type: ::std::option::Option<crate::types::ProtectedResourceType>,
    pub(crate) members: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) protection_group_arn: ::std::option::Option<::std::string::String>,
}
impl ProtectionGroupBuilder {
    /// <p>The name of the protection group. You use this to identify the protection group in lists and to manage the protection group, for example to update, delete, or describe it.</p>
    /// This field is required.
    pub fn protection_group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.protection_group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the protection group. You use this to identify the protection group in lists and to manage the protection group, for example to update, delete, or describe it.</p>
    pub fn set_protection_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.protection_group_id = input;
        self
    }
    /// <p>The name of the protection group. You use this to identify the protection group in lists and to manage the protection group, for example to update, delete, or describe it.</p>
    pub fn get_protection_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.protection_group_id
    }
    /// <p>Defines how Shield combines resource data for the group in order to detect, mitigate, and report events.</p>
    /// <ul>
    /// <li>
    /// <p>Sum - Use the total traffic across the group. This is a good choice for most cases. Examples include Elastic IP addresses for EC2 instances that scale manually or automatically.</p></li>
    /// <li>
    /// <p>Mean - Use the average of the traffic across the group. This is a good choice for resources that share traffic uniformly. Examples include accelerators and load balancers.</p></li>
    /// <li>
    /// <p>Max - Use the highest traffic from each resource. This is useful for resources that don't share traffic and for resources that share that traffic in a non-uniform way. Examples include Amazon CloudFront distributions and origin resources for CloudFront distributions.</p></li>
    /// </ul>
    /// This field is required.
    pub fn aggregation(mut self, input: crate::types::ProtectionGroupAggregation) -> Self {
        self.aggregation = ::std::option::Option::Some(input);
        self
    }
    /// <p>Defines how Shield combines resource data for the group in order to detect, mitigate, and report events.</p>
    /// <ul>
    /// <li>
    /// <p>Sum - Use the total traffic across the group. This is a good choice for most cases. Examples include Elastic IP addresses for EC2 instances that scale manually or automatically.</p></li>
    /// <li>
    /// <p>Mean - Use the average of the traffic across the group. This is a good choice for resources that share traffic uniformly. Examples include accelerators and load balancers.</p></li>
    /// <li>
    /// <p>Max - Use the highest traffic from each resource. This is useful for resources that don't share traffic and for resources that share that traffic in a non-uniform way. Examples include Amazon CloudFront distributions and origin resources for CloudFront distributions.</p></li>
    /// </ul>
    pub fn set_aggregation(mut self, input: ::std::option::Option<crate::types::ProtectionGroupAggregation>) -> Self {
        self.aggregation = input;
        self
    }
    /// <p>Defines how Shield combines resource data for the group in order to detect, mitigate, and report events.</p>
    /// <ul>
    /// <li>
    /// <p>Sum - Use the total traffic across the group. This is a good choice for most cases. Examples include Elastic IP addresses for EC2 instances that scale manually or automatically.</p></li>
    /// <li>
    /// <p>Mean - Use the average of the traffic across the group. This is a good choice for resources that share traffic uniformly. Examples include accelerators and load balancers.</p></li>
    /// <li>
    /// <p>Max - Use the highest traffic from each resource. This is useful for resources that don't share traffic and for resources that share that traffic in a non-uniform way. Examples include Amazon CloudFront distributions and origin resources for CloudFront distributions.</p></li>
    /// </ul>
    pub fn get_aggregation(&self) -> &::std::option::Option<crate::types::ProtectionGroupAggregation> {
        &self.aggregation
    }
    /// <p>The criteria to use to choose the protected resources for inclusion in the group. You can include all resources that have protections, provide a list of resource ARNs (Amazon Resource Names), or include all resources of a specified resource type.</p>
    /// This field is required.
    pub fn pattern(mut self, input: crate::types::ProtectionGroupPattern) -> Self {
        self.pattern = ::std::option::Option::Some(input);
        self
    }
    /// <p>The criteria to use to choose the protected resources for inclusion in the group. You can include all resources that have protections, provide a list of resource ARNs (Amazon Resource Names), or include all resources of a specified resource type.</p>
    pub fn set_pattern(mut self, input: ::std::option::Option<crate::types::ProtectionGroupPattern>) -> Self {
        self.pattern = input;
        self
    }
    /// <p>The criteria to use to choose the protected resources for inclusion in the group. You can include all resources that have protections, provide a list of resource ARNs (Amazon Resource Names), or include all resources of a specified resource type.</p>
    pub fn get_pattern(&self) -> &::std::option::Option<crate::types::ProtectionGroupPattern> {
        &self.pattern
    }
    /// <p>The resource type to include in the protection group. All protected resources of this type are included in the protection group. You must set this when you set <code>Pattern</code> to <code>BY_RESOURCE_TYPE</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub fn resource_type(mut self, input: crate::types::ProtectedResourceType) -> Self {
        self.resource_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource type to include in the protection group. All protected resources of this type are included in the protection group. You must set this when you set <code>Pattern</code> to <code>BY_RESOURCE_TYPE</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<crate::types::ProtectedResourceType>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The resource type to include in the protection group. All protected resources of this type are included in the protection group. You must set this when you set <code>Pattern</code> to <code>BY_RESOURCE_TYPE</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<crate::types::ProtectedResourceType> {
        &self.resource_type
    }
    /// Appends an item to `members`.
    ///
    /// To override the contents of this collection use [`set_members`](Self::set_members).
    ///
    /// <p>The ARNs (Amazon Resource Names) of the resources to include in the protection group. You must set this when you set <code>Pattern</code> to <code>ARBITRARY</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub fn members(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.members.unwrap_or_default();
        v.push(input.into());
        self.members = ::std::option::Option::Some(v);
        self
    }
    /// <p>The ARNs (Amazon Resource Names) of the resources to include in the protection group. You must set this when you set <code>Pattern</code> to <code>ARBITRARY</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub fn set_members(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.members = input;
        self
    }
    /// <p>The ARNs (Amazon Resource Names) of the resources to include in the protection group. You must set this when you set <code>Pattern</code> to <code>ARBITRARY</code> and you must not set it for any other <code>Pattern</code> setting.</p>
    pub fn get_members(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.members
    }
    /// <p>The ARN (Amazon Resource Name) of the protection group.</p>
    pub fn protection_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.protection_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN (Amazon Resource Name) of the protection group.</p>
    pub fn set_protection_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.protection_group_arn = input;
        self
    }
    /// <p>The ARN (Amazon Resource Name) of the protection group.</p>
    pub fn get_protection_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.protection_group_arn
    }
    /// Consumes the builder and constructs a [`ProtectionGroup`](crate::types::ProtectionGroup).
    /// This method will fail if any of the following fields are not set:
    /// - [`protection_group_id`](crate::types::builders::ProtectionGroupBuilder::protection_group_id)
    /// - [`aggregation`](crate::types::builders::ProtectionGroupBuilder::aggregation)
    /// - [`pattern`](crate::types::builders::ProtectionGroupBuilder::pattern)
    /// - [`members`](crate::types::builders::ProtectionGroupBuilder::members)
    pub fn build(self) -> ::std::result::Result<crate::types::ProtectionGroup, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ProtectionGroup {
            protection_group_id: self.protection_group_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "protection_group_id",
                    "protection_group_id was not specified but it is required when building ProtectionGroup",
                )
            })?,
            aggregation: self.aggregation.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "aggregation",
                    "aggregation was not specified but it is required when building ProtectionGroup",
                )
            })?,
            pattern: self.pattern.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pattern",
                    "pattern was not specified but it is required when building ProtectionGroup",
                )
            })?,
            resource_type: self.resource_type,
            members: self.members.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "members",
                    "members was not specified but it is required when building ProtectionGroup",
                )
            })?,
            protection_group_arn: self.protection_group_arn,
        })
    }
}
