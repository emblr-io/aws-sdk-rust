// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration that specifies how traffic is shifted from one version of a Lambda function to another version during an Lambda deployment, or from one Amazon ECS task set to another during an Amazon ECS deployment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TrafficRoutingConfig {
    /// <p>The type of traffic shifting (<code>TimeBasedCanary</code> or <code>TimeBasedLinear</code>) used by a deployment configuration.</p>
    pub r#type: ::std::option::Option<crate::types::TrafficRoutingType>,
    /// <p>A configuration that shifts traffic from one version of a Lambda function or ECS task set to another in two increments. The original and target Lambda function versions or ECS task sets are specified in the deployment's AppSpec file.</p>
    pub time_based_canary: ::std::option::Option<crate::types::TimeBasedCanary>,
    /// <p>A configuration that shifts traffic from one version of a Lambda function or Amazon ECS task set to another in equal increments, with an equal number of minutes between each increment. The original and target Lambda function versions or Amazon ECS task sets are specified in the deployment's AppSpec file.</p>
    pub time_based_linear: ::std::option::Option<crate::types::TimeBasedLinear>,
}
impl TrafficRoutingConfig {
    /// <p>The type of traffic shifting (<code>TimeBasedCanary</code> or <code>TimeBasedLinear</code>) used by a deployment configuration.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::TrafficRoutingType> {
        self.r#type.as_ref()
    }
    /// <p>A configuration that shifts traffic from one version of a Lambda function or ECS task set to another in two increments. The original and target Lambda function versions or ECS task sets are specified in the deployment's AppSpec file.</p>
    pub fn time_based_canary(&self) -> ::std::option::Option<&crate::types::TimeBasedCanary> {
        self.time_based_canary.as_ref()
    }
    /// <p>A configuration that shifts traffic from one version of a Lambda function or Amazon ECS task set to another in equal increments, with an equal number of minutes between each increment. The original and target Lambda function versions or Amazon ECS task sets are specified in the deployment's AppSpec file.</p>
    pub fn time_based_linear(&self) -> ::std::option::Option<&crate::types::TimeBasedLinear> {
        self.time_based_linear.as_ref()
    }
}
impl TrafficRoutingConfig {
    /// Creates a new builder-style object to manufacture [`TrafficRoutingConfig`](crate::types::TrafficRoutingConfig).
    pub fn builder() -> crate::types::builders::TrafficRoutingConfigBuilder {
        crate::types::builders::TrafficRoutingConfigBuilder::default()
    }
}

/// A builder for [`TrafficRoutingConfig`](crate::types::TrafficRoutingConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TrafficRoutingConfigBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::TrafficRoutingType>,
    pub(crate) time_based_canary: ::std::option::Option<crate::types::TimeBasedCanary>,
    pub(crate) time_based_linear: ::std::option::Option<crate::types::TimeBasedLinear>,
}
impl TrafficRoutingConfigBuilder {
    /// <p>The type of traffic shifting (<code>TimeBasedCanary</code> or <code>TimeBasedLinear</code>) used by a deployment configuration.</p>
    pub fn r#type(mut self, input: crate::types::TrafficRoutingType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of traffic shifting (<code>TimeBasedCanary</code> or <code>TimeBasedLinear</code>) used by a deployment configuration.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::TrafficRoutingType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of traffic shifting (<code>TimeBasedCanary</code> or <code>TimeBasedLinear</code>) used by a deployment configuration.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::TrafficRoutingType> {
        &self.r#type
    }
    /// <p>A configuration that shifts traffic from one version of a Lambda function or ECS task set to another in two increments. The original and target Lambda function versions or ECS task sets are specified in the deployment's AppSpec file.</p>
    pub fn time_based_canary(mut self, input: crate::types::TimeBasedCanary) -> Self {
        self.time_based_canary = ::std::option::Option::Some(input);
        self
    }
    /// <p>A configuration that shifts traffic from one version of a Lambda function or ECS task set to another in two increments. The original and target Lambda function versions or ECS task sets are specified in the deployment's AppSpec file.</p>
    pub fn set_time_based_canary(mut self, input: ::std::option::Option<crate::types::TimeBasedCanary>) -> Self {
        self.time_based_canary = input;
        self
    }
    /// <p>A configuration that shifts traffic from one version of a Lambda function or ECS task set to another in two increments. The original and target Lambda function versions or ECS task sets are specified in the deployment's AppSpec file.</p>
    pub fn get_time_based_canary(&self) -> &::std::option::Option<crate::types::TimeBasedCanary> {
        &self.time_based_canary
    }
    /// <p>A configuration that shifts traffic from one version of a Lambda function or Amazon ECS task set to another in equal increments, with an equal number of minutes between each increment. The original and target Lambda function versions or Amazon ECS task sets are specified in the deployment's AppSpec file.</p>
    pub fn time_based_linear(mut self, input: crate::types::TimeBasedLinear) -> Self {
        self.time_based_linear = ::std::option::Option::Some(input);
        self
    }
    /// <p>A configuration that shifts traffic from one version of a Lambda function or Amazon ECS task set to another in equal increments, with an equal number of minutes between each increment. The original and target Lambda function versions or Amazon ECS task sets are specified in the deployment's AppSpec file.</p>
    pub fn set_time_based_linear(mut self, input: ::std::option::Option<crate::types::TimeBasedLinear>) -> Self {
        self.time_based_linear = input;
        self
    }
    /// <p>A configuration that shifts traffic from one version of a Lambda function or Amazon ECS task set to another in equal increments, with an equal number of minutes between each increment. The original and target Lambda function versions or Amazon ECS task sets are specified in the deployment's AppSpec file.</p>
    pub fn get_time_based_linear(&self) -> &::std::option::Option<crate::types::TimeBasedLinear> {
        &self.time_based_linear
    }
    /// Consumes the builder and constructs a [`TrafficRoutingConfig`](crate::types::TrafficRoutingConfig).
    pub fn build(self) -> crate::types::TrafficRoutingConfig {
        crate::types::TrafficRoutingConfig {
            r#type: self.r#type,
            time_based_canary: self.time_based_canary,
            time_based_linear: self.time_based_linear,
        }
    }
}
