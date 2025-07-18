// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of a capacity provider strategy. A capacity provider strategy can be set when using the <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html">RunTask</a>or <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateCluster.html">CreateCluster</a> APIs or as the default capacity provider strategy for a cluster with the <code>CreateCluster</code> API.</p>
/// <p>Only capacity providers that are already associated with a cluster and have an <code>ACTIVE</code> or <code>UPDATING</code> status can be used in a capacity provider strategy. The <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_PutClusterCapacityProviders.html">PutClusterCapacityProviders</a> API is used to associate a capacity provider with a cluster.</p>
/// <p>If specifying a capacity provider that uses an Auto Scaling group, the capacity provider must already be created. New Auto Scaling group capacity providers can be created with the <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_CreateClusterCapacityProvider.html">CreateClusterCapacityProvider</a> API operation.</p>
/// <p>To use a Fargate capacity provider, specify either the <code>FARGATE</code> or <code>FARGATE_SPOT</code> capacity providers. The Fargate capacity providers are available to all accounts and only need to be associated with a cluster to be used in a capacity provider strategy.</p>
/// <p>With <code>FARGATE_SPOT</code>, you can run interruption tolerant tasks at a rate that's discounted compared to the <code>FARGATE</code> price. <code>FARGATE_SPOT</code> runs tasks on spare compute capacity. When Amazon Web Services needs the capacity back, your tasks are interrupted with a two-minute warning. <code>FARGATE_SPOT</code> supports Linux tasks with the X86_64 architecture on platform version 1.3.0 or later. <code>FARGATE_SPOT</code> supports Linux tasks with the ARM64 architecture on platform version 1.4.0 or later.</p>
/// <p>A capacity provider strategy can contain a maximum of 20 capacity providers.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CapacityProviderStrategyItem {
    /// <p>The short name of the capacity provider.</p>
    pub capacity_provider: ::std::string::String,
    /// <p>The <i>weight</i> value designates the relative percentage of the total number of tasks launched that should use the specified capacity provider. The <code>weight</code> value is taken into consideration after the <code>base</code> value, if defined, is satisfied.</p>
    /// <p>If no <code>weight</code> value is specified, the default value of <code>0</code> is used. When multiple capacity providers are specified within a capacity provider strategy, at least one of the capacity providers must have a weight value greater than zero and any capacity providers with a weight of <code>0</code> can't be used to place tasks. If you specify multiple capacity providers in a strategy that all have a weight of <code>0</code>, any <code>RunTask</code> or <code>CreateService</code> actions using the capacity provider strategy will fail.</p>
    /// <p>An example scenario for using weights is defining a strategy that contains two capacity providers and both have a weight of <code>1</code>, then when the <code>base</code> is satisfied, the tasks will be split evenly across the two capacity providers. Using that same logic, if you specify a weight of <code>1</code> for <i>capacityProviderA</i> and a weight of <code>4</code> for <i>capacityProviderB</i>, then for every one task that's run using <i>capacityProviderA</i>, four tasks would use <i>capacityProviderB</i>.</p>
    pub weight: i32,
    /// <p>The <i>base</i> value designates how many tasks, at a minimum, to run on the specified capacity provider. Only one capacity provider in a capacity provider strategy can have a <i>base</i> defined. If no value is specified, the default value of <code>0</code> is used.</p>
    pub base: i32,
}
impl CapacityProviderStrategyItem {
    /// <p>The short name of the capacity provider.</p>
    pub fn capacity_provider(&self) -> &str {
        use std::ops::Deref;
        self.capacity_provider.deref()
    }
    /// <p>The <i>weight</i> value designates the relative percentage of the total number of tasks launched that should use the specified capacity provider. The <code>weight</code> value is taken into consideration after the <code>base</code> value, if defined, is satisfied.</p>
    /// <p>If no <code>weight</code> value is specified, the default value of <code>0</code> is used. When multiple capacity providers are specified within a capacity provider strategy, at least one of the capacity providers must have a weight value greater than zero and any capacity providers with a weight of <code>0</code> can't be used to place tasks. If you specify multiple capacity providers in a strategy that all have a weight of <code>0</code>, any <code>RunTask</code> or <code>CreateService</code> actions using the capacity provider strategy will fail.</p>
    /// <p>An example scenario for using weights is defining a strategy that contains two capacity providers and both have a weight of <code>1</code>, then when the <code>base</code> is satisfied, the tasks will be split evenly across the two capacity providers. Using that same logic, if you specify a weight of <code>1</code> for <i>capacityProviderA</i> and a weight of <code>4</code> for <i>capacityProviderB</i>, then for every one task that's run using <i>capacityProviderA</i>, four tasks would use <i>capacityProviderB</i>.</p>
    pub fn weight(&self) -> i32 {
        self.weight
    }
    /// <p>The <i>base</i> value designates how many tasks, at a minimum, to run on the specified capacity provider. Only one capacity provider in a capacity provider strategy can have a <i>base</i> defined. If no value is specified, the default value of <code>0</code> is used.</p>
    pub fn base(&self) -> i32 {
        self.base
    }
}
impl CapacityProviderStrategyItem {
    /// Creates a new builder-style object to manufacture [`CapacityProviderStrategyItem`](crate::types::CapacityProviderStrategyItem).
    pub fn builder() -> crate::types::builders::CapacityProviderStrategyItemBuilder {
        crate::types::builders::CapacityProviderStrategyItemBuilder::default()
    }
}

/// A builder for [`CapacityProviderStrategyItem`](crate::types::CapacityProviderStrategyItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CapacityProviderStrategyItemBuilder {
    pub(crate) capacity_provider: ::std::option::Option<::std::string::String>,
    pub(crate) weight: ::std::option::Option<i32>,
    pub(crate) base: ::std::option::Option<i32>,
}
impl CapacityProviderStrategyItemBuilder {
    /// <p>The short name of the capacity provider.</p>
    /// This field is required.
    pub fn capacity_provider(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.capacity_provider = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The short name of the capacity provider.</p>
    pub fn set_capacity_provider(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.capacity_provider = input;
        self
    }
    /// <p>The short name of the capacity provider.</p>
    pub fn get_capacity_provider(&self) -> &::std::option::Option<::std::string::String> {
        &self.capacity_provider
    }
    /// <p>The <i>weight</i> value designates the relative percentage of the total number of tasks launched that should use the specified capacity provider. The <code>weight</code> value is taken into consideration after the <code>base</code> value, if defined, is satisfied.</p>
    /// <p>If no <code>weight</code> value is specified, the default value of <code>0</code> is used. When multiple capacity providers are specified within a capacity provider strategy, at least one of the capacity providers must have a weight value greater than zero and any capacity providers with a weight of <code>0</code> can't be used to place tasks. If you specify multiple capacity providers in a strategy that all have a weight of <code>0</code>, any <code>RunTask</code> or <code>CreateService</code> actions using the capacity provider strategy will fail.</p>
    /// <p>An example scenario for using weights is defining a strategy that contains two capacity providers and both have a weight of <code>1</code>, then when the <code>base</code> is satisfied, the tasks will be split evenly across the two capacity providers. Using that same logic, if you specify a weight of <code>1</code> for <i>capacityProviderA</i> and a weight of <code>4</code> for <i>capacityProviderB</i>, then for every one task that's run using <i>capacityProviderA</i>, four tasks would use <i>capacityProviderB</i>.</p>
    pub fn weight(mut self, input: i32) -> Self {
        self.weight = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <i>weight</i> value designates the relative percentage of the total number of tasks launched that should use the specified capacity provider. The <code>weight</code> value is taken into consideration after the <code>base</code> value, if defined, is satisfied.</p>
    /// <p>If no <code>weight</code> value is specified, the default value of <code>0</code> is used. When multiple capacity providers are specified within a capacity provider strategy, at least one of the capacity providers must have a weight value greater than zero and any capacity providers with a weight of <code>0</code> can't be used to place tasks. If you specify multiple capacity providers in a strategy that all have a weight of <code>0</code>, any <code>RunTask</code> or <code>CreateService</code> actions using the capacity provider strategy will fail.</p>
    /// <p>An example scenario for using weights is defining a strategy that contains two capacity providers and both have a weight of <code>1</code>, then when the <code>base</code> is satisfied, the tasks will be split evenly across the two capacity providers. Using that same logic, if you specify a weight of <code>1</code> for <i>capacityProviderA</i> and a weight of <code>4</code> for <i>capacityProviderB</i>, then for every one task that's run using <i>capacityProviderA</i>, four tasks would use <i>capacityProviderB</i>.</p>
    pub fn set_weight(mut self, input: ::std::option::Option<i32>) -> Self {
        self.weight = input;
        self
    }
    /// <p>The <i>weight</i> value designates the relative percentage of the total number of tasks launched that should use the specified capacity provider. The <code>weight</code> value is taken into consideration after the <code>base</code> value, if defined, is satisfied.</p>
    /// <p>If no <code>weight</code> value is specified, the default value of <code>0</code> is used. When multiple capacity providers are specified within a capacity provider strategy, at least one of the capacity providers must have a weight value greater than zero and any capacity providers with a weight of <code>0</code> can't be used to place tasks. If you specify multiple capacity providers in a strategy that all have a weight of <code>0</code>, any <code>RunTask</code> or <code>CreateService</code> actions using the capacity provider strategy will fail.</p>
    /// <p>An example scenario for using weights is defining a strategy that contains two capacity providers and both have a weight of <code>1</code>, then when the <code>base</code> is satisfied, the tasks will be split evenly across the two capacity providers. Using that same logic, if you specify a weight of <code>1</code> for <i>capacityProviderA</i> and a weight of <code>4</code> for <i>capacityProviderB</i>, then for every one task that's run using <i>capacityProviderA</i>, four tasks would use <i>capacityProviderB</i>.</p>
    pub fn get_weight(&self) -> &::std::option::Option<i32> {
        &self.weight
    }
    /// <p>The <i>base</i> value designates how many tasks, at a minimum, to run on the specified capacity provider. Only one capacity provider in a capacity provider strategy can have a <i>base</i> defined. If no value is specified, the default value of <code>0</code> is used.</p>
    pub fn base(mut self, input: i32) -> Self {
        self.base = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <i>base</i> value designates how many tasks, at a minimum, to run on the specified capacity provider. Only one capacity provider in a capacity provider strategy can have a <i>base</i> defined. If no value is specified, the default value of <code>0</code> is used.</p>
    pub fn set_base(mut self, input: ::std::option::Option<i32>) -> Self {
        self.base = input;
        self
    }
    /// <p>The <i>base</i> value designates how many tasks, at a minimum, to run on the specified capacity provider. Only one capacity provider in a capacity provider strategy can have a <i>base</i> defined. If no value is specified, the default value of <code>0</code> is used.</p>
    pub fn get_base(&self) -> &::std::option::Option<i32> {
        &self.base
    }
    /// Consumes the builder and constructs a [`CapacityProviderStrategyItem`](crate::types::CapacityProviderStrategyItem).
    /// This method will fail if any of the following fields are not set:
    /// - [`capacity_provider`](crate::types::builders::CapacityProviderStrategyItemBuilder::capacity_provider)
    pub fn build(self) -> ::std::result::Result<crate::types::CapacityProviderStrategyItem, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CapacityProviderStrategyItem {
            capacity_provider: self.capacity_provider.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "capacity_provider",
                    "capacity_provider was not specified but it is required when building CapacityProviderStrategyItem",
                )
            })?,
            weight: self.weight.unwrap_or_default(),
            base: self.base.unwrap_or_default(),
        })
    }
}
