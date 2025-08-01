// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a standalone resource or similarly grouped resources that the application is made up of.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ApplicationComponent {
    /// <p>The name of the component.</p>
    pub component_name: ::std::option::Option<::std::string::String>,
    /// <p>If logging is supported for the resource type, indicates whether the component has configured logs to be monitored.</p>
    pub component_remarks: ::std::option::Option<::std::string::String>,
    /// <p>The resource type. Supported resource types include EC2 instances, Auto Scaling group, Classic ELB, Application ELB, and SQS Queue.</p>
    pub resource_type: ::std::option::Option<::std::string::String>,
    /// <p>The operating system of the component.</p>
    pub os_type: ::std::option::Option<crate::types::OsType>,
    /// <p>The stack tier of the application component.</p>
    pub tier: ::std::option::Option<crate::types::Tier>,
    /// <p>Indicates whether the application component is monitored.</p>
    pub monitor: ::std::option::Option<bool>,
    /// <p>Workloads detected in the application component.</p>
    pub detected_workload: ::std::option::Option<
        ::std::collections::HashMap<crate::types::Tier, ::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    >,
}
impl ApplicationComponent {
    /// <p>The name of the component.</p>
    pub fn component_name(&self) -> ::std::option::Option<&str> {
        self.component_name.as_deref()
    }
    /// <p>If logging is supported for the resource type, indicates whether the component has configured logs to be monitored.</p>
    pub fn component_remarks(&self) -> ::std::option::Option<&str> {
        self.component_remarks.as_deref()
    }
    /// <p>The resource type. Supported resource types include EC2 instances, Auto Scaling group, Classic ELB, Application ELB, and SQS Queue.</p>
    pub fn resource_type(&self) -> ::std::option::Option<&str> {
        self.resource_type.as_deref()
    }
    /// <p>The operating system of the component.</p>
    pub fn os_type(&self) -> ::std::option::Option<&crate::types::OsType> {
        self.os_type.as_ref()
    }
    /// <p>The stack tier of the application component.</p>
    pub fn tier(&self) -> ::std::option::Option<&crate::types::Tier> {
        self.tier.as_ref()
    }
    /// <p>Indicates whether the application component is monitored.</p>
    pub fn monitor(&self) -> ::std::option::Option<bool> {
        self.monitor
    }
    /// <p>Workloads detected in the application component.</p>
    pub fn detected_workload(
        &self,
    ) -> ::std::option::Option<
        &::std::collections::HashMap<crate::types::Tier, ::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    > {
        self.detected_workload.as_ref()
    }
}
impl ApplicationComponent {
    /// Creates a new builder-style object to manufacture [`ApplicationComponent`](crate::types::ApplicationComponent).
    pub fn builder() -> crate::types::builders::ApplicationComponentBuilder {
        crate::types::builders::ApplicationComponentBuilder::default()
    }
}

/// A builder for [`ApplicationComponent`](crate::types::ApplicationComponent).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ApplicationComponentBuilder {
    pub(crate) component_name: ::std::option::Option<::std::string::String>,
    pub(crate) component_remarks: ::std::option::Option<::std::string::String>,
    pub(crate) resource_type: ::std::option::Option<::std::string::String>,
    pub(crate) os_type: ::std::option::Option<crate::types::OsType>,
    pub(crate) tier: ::std::option::Option<crate::types::Tier>,
    pub(crate) monitor: ::std::option::Option<bool>,
    pub(crate) detected_workload: ::std::option::Option<
        ::std::collections::HashMap<crate::types::Tier, ::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    >,
}
impl ApplicationComponentBuilder {
    /// <p>The name of the component.</p>
    pub fn component_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the component.</p>
    pub fn set_component_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_name = input;
        self
    }
    /// <p>The name of the component.</p>
    pub fn get_component_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_name
    }
    /// <p>If logging is supported for the resource type, indicates whether the component has configured logs to be monitored.</p>
    pub fn component_remarks(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.component_remarks = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If logging is supported for the resource type, indicates whether the component has configured logs to be monitored.</p>
    pub fn set_component_remarks(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.component_remarks = input;
        self
    }
    /// <p>If logging is supported for the resource type, indicates whether the component has configured logs to be monitored.</p>
    pub fn get_component_remarks(&self) -> &::std::option::Option<::std::string::String> {
        &self.component_remarks
    }
    /// <p>The resource type. Supported resource types include EC2 instances, Auto Scaling group, Classic ELB, Application ELB, and SQS Queue.</p>
    pub fn resource_type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The resource type. Supported resource types include EC2 instances, Auto Scaling group, Classic ELB, Application ELB, and SQS Queue.</p>
    pub fn set_resource_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_type = input;
        self
    }
    /// <p>The resource type. Supported resource types include EC2 instances, Auto Scaling group, Classic ELB, Application ELB, and SQS Queue.</p>
    pub fn get_resource_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_type
    }
    /// <p>The operating system of the component.</p>
    pub fn os_type(mut self, input: crate::types::OsType) -> Self {
        self.os_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The operating system of the component.</p>
    pub fn set_os_type(mut self, input: ::std::option::Option<crate::types::OsType>) -> Self {
        self.os_type = input;
        self
    }
    /// <p>The operating system of the component.</p>
    pub fn get_os_type(&self) -> &::std::option::Option<crate::types::OsType> {
        &self.os_type
    }
    /// <p>The stack tier of the application component.</p>
    pub fn tier(mut self, input: crate::types::Tier) -> Self {
        self.tier = ::std::option::Option::Some(input);
        self
    }
    /// <p>The stack tier of the application component.</p>
    pub fn set_tier(mut self, input: ::std::option::Option<crate::types::Tier>) -> Self {
        self.tier = input;
        self
    }
    /// <p>The stack tier of the application component.</p>
    pub fn get_tier(&self) -> &::std::option::Option<crate::types::Tier> {
        &self.tier
    }
    /// <p>Indicates whether the application component is monitored.</p>
    pub fn monitor(mut self, input: bool) -> Self {
        self.monitor = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the application component is monitored.</p>
    pub fn set_monitor(mut self, input: ::std::option::Option<bool>) -> Self {
        self.monitor = input;
        self
    }
    /// <p>Indicates whether the application component is monitored.</p>
    pub fn get_monitor(&self) -> &::std::option::Option<bool> {
        &self.monitor
    }
    /// Adds a key-value pair to `detected_workload`.
    ///
    /// To override the contents of this collection use [`set_detected_workload`](Self::set_detected_workload).
    ///
    /// <p>Workloads detected in the application component.</p>
    pub fn detected_workload(mut self, k: crate::types::Tier, v: ::std::collections::HashMap<::std::string::String, ::std::string::String>) -> Self {
        let mut hash_map = self.detected_workload.unwrap_or_default();
        hash_map.insert(k, v);
        self.detected_workload = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Workloads detected in the application component.</p>
    pub fn set_detected_workload(
        mut self,
        input: ::std::option::Option<
            ::std::collections::HashMap<crate::types::Tier, ::std::collections::HashMap<::std::string::String, ::std::string::String>>,
        >,
    ) -> Self {
        self.detected_workload = input;
        self
    }
    /// <p>Workloads detected in the application component.</p>
    pub fn get_detected_workload(
        &self,
    ) -> &::std::option::Option<
        ::std::collections::HashMap<crate::types::Tier, ::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    > {
        &self.detected_workload
    }
    /// Consumes the builder and constructs a [`ApplicationComponent`](crate::types::ApplicationComponent).
    pub fn build(self) -> crate::types::ApplicationComponent {
        crate::types::ApplicationComponent {
            component_name: self.component_name,
            component_remarks: self.component_remarks,
            resource_type: self.resource_type,
            os_type: self.os_type,
            tier: self.tier,
            monitor: self.monitor,
            detected_workload: self.detected_workload,
        }
    }
}
