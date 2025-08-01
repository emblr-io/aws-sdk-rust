// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Summarizes the number of layers, instances, and apps in a stack.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StackSummary {
    /// <p>The stack ID.</p>
    pub stack_id: ::std::option::Option<::std::string::String>,
    /// <p>The stack name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The stack's ARN.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The number of layers.</p>
    pub layers_count: ::std::option::Option<i32>,
    /// <p>The number of apps.</p>
    pub apps_count: ::std::option::Option<i32>,
    /// <p>An <code>InstancesCount</code> object with the number of instances in each status.</p>
    pub instances_count: ::std::option::Option<crate::types::InstancesCount>,
}
impl StackSummary {
    /// <p>The stack ID.</p>
    pub fn stack_id(&self) -> ::std::option::Option<&str> {
        self.stack_id.as_deref()
    }
    /// <p>The stack name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The stack's ARN.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The number of layers.</p>
    pub fn layers_count(&self) -> ::std::option::Option<i32> {
        self.layers_count
    }
    /// <p>The number of apps.</p>
    pub fn apps_count(&self) -> ::std::option::Option<i32> {
        self.apps_count
    }
    /// <p>An <code>InstancesCount</code> object with the number of instances in each status.</p>
    pub fn instances_count(&self) -> ::std::option::Option<&crate::types::InstancesCount> {
        self.instances_count.as_ref()
    }
}
impl StackSummary {
    /// Creates a new builder-style object to manufacture [`StackSummary`](crate::types::StackSummary).
    pub fn builder() -> crate::types::builders::StackSummaryBuilder {
        crate::types::builders::StackSummaryBuilder::default()
    }
}

/// A builder for [`StackSummary`](crate::types::StackSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StackSummaryBuilder {
    pub(crate) stack_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) layers_count: ::std::option::Option<i32>,
    pub(crate) apps_count: ::std::option::Option<i32>,
    pub(crate) instances_count: ::std::option::Option<crate::types::InstancesCount>,
}
impl StackSummaryBuilder {
    /// <p>The stack ID.</p>
    pub fn stack_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stack ID.</p>
    pub fn set_stack_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_id = input;
        self
    }
    /// <p>The stack ID.</p>
    pub fn get_stack_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_id
    }
    /// <p>The stack name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stack name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The stack name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The stack's ARN.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The stack's ARN.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The stack's ARN.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The number of layers.</p>
    pub fn layers_count(mut self, input: i32) -> Self {
        self.layers_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of layers.</p>
    pub fn set_layers_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.layers_count = input;
        self
    }
    /// <p>The number of layers.</p>
    pub fn get_layers_count(&self) -> &::std::option::Option<i32> {
        &self.layers_count
    }
    /// <p>The number of apps.</p>
    pub fn apps_count(mut self, input: i32) -> Self {
        self.apps_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of apps.</p>
    pub fn set_apps_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.apps_count = input;
        self
    }
    /// <p>The number of apps.</p>
    pub fn get_apps_count(&self) -> &::std::option::Option<i32> {
        &self.apps_count
    }
    /// <p>An <code>InstancesCount</code> object with the number of instances in each status.</p>
    pub fn instances_count(mut self, input: crate::types::InstancesCount) -> Self {
        self.instances_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>An <code>InstancesCount</code> object with the number of instances in each status.</p>
    pub fn set_instances_count(mut self, input: ::std::option::Option<crate::types::InstancesCount>) -> Self {
        self.instances_count = input;
        self
    }
    /// <p>An <code>InstancesCount</code> object with the number of instances in each status.</p>
    pub fn get_instances_count(&self) -> &::std::option::Option<crate::types::InstancesCount> {
        &self.instances_count
    }
    /// Consumes the builder and constructs a [`StackSummary`](crate::types::StackSummary).
    pub fn build(self) -> crate::types::StackSummary {
        crate::types::StackSummary {
            stack_id: self.stack_id,
            name: self.name,
            arn: self.arn,
            layers_count: self.layers_count,
            apps_count: self.apps_count,
            instances_count: self.instances_count,
        }
    }
}
