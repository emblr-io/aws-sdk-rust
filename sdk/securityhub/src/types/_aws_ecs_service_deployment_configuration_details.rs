// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Optional deployment parameters for the service.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEcsServiceDeploymentConfigurationDetails {
    /// <p>Determines whether a service deployment fails if a service cannot reach a steady state.</p>
    pub deployment_circuit_breaker: ::std::option::Option<crate::types::AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails>,
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the maximum number of tasks in a service that are allowed in the <code>RUNNING</code> or <code>PENDING</code> state during a deployment, and for tasks that use the EC2 launch type, when any container instances are in the <code>DRAINING</code> state. Provided as a percentage of the desired number of tasks. The default value is 200%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types, and tasks that use the EC2 launch type, the maximum number of tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the maximum percent value is not used.</p>
    pub maximum_percent: ::std::option::Option<i32>,
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the minimum number of tasks in a service that must remain in the <code>RUNNING</code> state during a deployment, and while any container instances are in the <code>DRAINING</code> state if the service contains tasks using the EC2 launch type. Expressed as a percentage of the desired number of tasks. The default value is 100%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types and tasks that use the EC2 launch type, the minimum number of the tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the minimum healthy percent value is not used.</p>
    pub minimum_healthy_percent: ::std::option::Option<i32>,
}
impl AwsEcsServiceDeploymentConfigurationDetails {
    /// <p>Determines whether a service deployment fails if a service cannot reach a steady state.</p>
    pub fn deployment_circuit_breaker(
        &self,
    ) -> ::std::option::Option<&crate::types::AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails> {
        self.deployment_circuit_breaker.as_ref()
    }
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the maximum number of tasks in a service that are allowed in the <code>RUNNING</code> or <code>PENDING</code> state during a deployment, and for tasks that use the EC2 launch type, when any container instances are in the <code>DRAINING</code> state. Provided as a percentage of the desired number of tasks. The default value is 200%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types, and tasks that use the EC2 launch type, the maximum number of tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the maximum percent value is not used.</p>
    pub fn maximum_percent(&self) -> ::std::option::Option<i32> {
        self.maximum_percent
    }
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the minimum number of tasks in a service that must remain in the <code>RUNNING</code> state during a deployment, and while any container instances are in the <code>DRAINING</code> state if the service contains tasks using the EC2 launch type. Expressed as a percentage of the desired number of tasks. The default value is 100%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types and tasks that use the EC2 launch type, the minimum number of the tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the minimum healthy percent value is not used.</p>
    pub fn minimum_healthy_percent(&self) -> ::std::option::Option<i32> {
        self.minimum_healthy_percent
    }
}
impl AwsEcsServiceDeploymentConfigurationDetails {
    /// Creates a new builder-style object to manufacture [`AwsEcsServiceDeploymentConfigurationDetails`](crate::types::AwsEcsServiceDeploymentConfigurationDetails).
    pub fn builder() -> crate::types::builders::AwsEcsServiceDeploymentConfigurationDetailsBuilder {
        crate::types::builders::AwsEcsServiceDeploymentConfigurationDetailsBuilder::default()
    }
}

/// A builder for [`AwsEcsServiceDeploymentConfigurationDetails`](crate::types::AwsEcsServiceDeploymentConfigurationDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEcsServiceDeploymentConfigurationDetailsBuilder {
    pub(crate) deployment_circuit_breaker: ::std::option::Option<crate::types::AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails>,
    pub(crate) maximum_percent: ::std::option::Option<i32>,
    pub(crate) minimum_healthy_percent: ::std::option::Option<i32>,
}
impl AwsEcsServiceDeploymentConfigurationDetailsBuilder {
    /// <p>Determines whether a service deployment fails if a service cannot reach a steady state.</p>
    pub fn deployment_circuit_breaker(mut self, input: crate::types::AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails) -> Self {
        self.deployment_circuit_breaker = ::std::option::Option::Some(input);
        self
    }
    /// <p>Determines whether a service deployment fails if a service cannot reach a steady state.</p>
    pub fn set_deployment_circuit_breaker(
        mut self,
        input: ::std::option::Option<crate::types::AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails>,
    ) -> Self {
        self.deployment_circuit_breaker = input;
        self
    }
    /// <p>Determines whether a service deployment fails if a service cannot reach a steady state.</p>
    pub fn get_deployment_circuit_breaker(
        &self,
    ) -> &::std::option::Option<crate::types::AwsEcsServiceDeploymentConfigurationDeploymentCircuitBreakerDetails> {
        &self.deployment_circuit_breaker
    }
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the maximum number of tasks in a service that are allowed in the <code>RUNNING</code> or <code>PENDING</code> state during a deployment, and for tasks that use the EC2 launch type, when any container instances are in the <code>DRAINING</code> state. Provided as a percentage of the desired number of tasks. The default value is 200%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types, and tasks that use the EC2 launch type, the maximum number of tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the maximum percent value is not used.</p>
    pub fn maximum_percent(mut self, input: i32) -> Self {
        self.maximum_percent = ::std::option::Option::Some(input);
        self
    }
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the maximum number of tasks in a service that are allowed in the <code>RUNNING</code> or <code>PENDING</code> state during a deployment, and for tasks that use the EC2 launch type, when any container instances are in the <code>DRAINING</code> state. Provided as a percentage of the desired number of tasks. The default value is 200%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types, and tasks that use the EC2 launch type, the maximum number of tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the maximum percent value is not used.</p>
    pub fn set_maximum_percent(mut self, input: ::std::option::Option<i32>) -> Self {
        self.maximum_percent = input;
        self
    }
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the maximum number of tasks in a service that are allowed in the <code>RUNNING</code> or <code>PENDING</code> state during a deployment, and for tasks that use the EC2 launch type, when any container instances are in the <code>DRAINING</code> state. Provided as a percentage of the desired number of tasks. The default value is 200%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types, and tasks that use the EC2 launch type, the maximum number of tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the maximum percent value is not used.</p>
    pub fn get_maximum_percent(&self) -> &::std::option::Option<i32> {
        &self.maximum_percent
    }
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the minimum number of tasks in a service that must remain in the <code>RUNNING</code> state during a deployment, and while any container instances are in the <code>DRAINING</code> state if the service contains tasks using the EC2 launch type. Expressed as a percentage of the desired number of tasks. The default value is 100%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types and tasks that use the EC2 launch type, the minimum number of the tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the minimum healthy percent value is not used.</p>
    pub fn minimum_healthy_percent(mut self, input: i32) -> Self {
        self.minimum_healthy_percent = ::std::option::Option::Some(input);
        self
    }
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the minimum number of tasks in a service that must remain in the <code>RUNNING</code> state during a deployment, and while any container instances are in the <code>DRAINING</code> state if the service contains tasks using the EC2 launch type. Expressed as a percentage of the desired number of tasks. The default value is 100%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types and tasks that use the EC2 launch type, the minimum number of the tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the minimum healthy percent value is not used.</p>
    pub fn set_minimum_healthy_percent(mut self, input: ::std::option::Option<i32>) -> Self {
        self.minimum_healthy_percent = input;
        self
    }
    /// <p>For a service that uses the rolling update (<code>ECS</code>) deployment type, the minimum number of tasks in a service that must remain in the <code>RUNNING</code> state during a deployment, and while any container instances are in the <code>DRAINING</code> state if the service contains tasks using the EC2 launch type. Expressed as a percentage of the desired number of tasks. The default value is 100%.</p>
    /// <p>For a service that uses the blue/green (<code>CODE_DEPLOY</code>) or <code>EXTERNAL</code> deployment types and tasks that use the EC2 launch type, the minimum number of the tasks in the service that remain in the <code>RUNNING</code> state while the container instances are in the <code>DRAINING</code> state.</p>
    /// <p>For the Fargate launch type, the minimum healthy percent value is not used.</p>
    pub fn get_minimum_healthy_percent(&self) -> &::std::option::Option<i32> {
        &self.minimum_healthy_percent
    }
    /// Consumes the builder and constructs a [`AwsEcsServiceDeploymentConfigurationDetails`](crate::types::AwsEcsServiceDeploymentConfigurationDetails).
    pub fn build(self) -> crate::types::AwsEcsServiceDeploymentConfigurationDetails {
        crate::types::AwsEcsServiceDeploymentConfigurationDetails {
            deployment_circuit_breaker: self.deployment_circuit_breaker,
            maximum_percent: self.maximum_percent,
            minimum_healthy_percent: self.minimum_healthy_percent,
        }
    }
}
