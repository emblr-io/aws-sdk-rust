// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about how traffic is rerouted to instances in a replacement environment in a blue/green deployment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeploymentReadyOption {
    /// <p>Information about when to reroute traffic from an original environment to a replacement environment in a blue/green deployment.</p>
    /// <ul>
    /// <li>
    /// <p>CONTINUE_DEPLOYMENT: Register new instances with the load balancer immediately after the new application revision is installed on the instances in the replacement environment.</p></li>
    /// <li>
    /// <p>STOP_DEPLOYMENT: Do not register new instances with a load balancer unless traffic rerouting is started using <code>ContinueDeployment</code>. If traffic rerouting is not started before the end of the specified wait period, the deployment status is changed to Stopped.</p></li>
    /// </ul>
    pub action_on_timeout: ::std::option::Option<crate::types::DeploymentReadyAction>,
    /// <p>The number of minutes to wait before the status of a blue/green deployment is changed to Stopped if rerouting is not started manually. Applies only to the <code>STOP_DEPLOYMENT</code> option for <code>actionOnTimeout</code>.</p>
    pub wait_time_in_minutes: i32,
}
impl DeploymentReadyOption {
    /// <p>Information about when to reroute traffic from an original environment to a replacement environment in a blue/green deployment.</p>
    /// <ul>
    /// <li>
    /// <p>CONTINUE_DEPLOYMENT: Register new instances with the load balancer immediately after the new application revision is installed on the instances in the replacement environment.</p></li>
    /// <li>
    /// <p>STOP_DEPLOYMENT: Do not register new instances with a load balancer unless traffic rerouting is started using <code>ContinueDeployment</code>. If traffic rerouting is not started before the end of the specified wait period, the deployment status is changed to Stopped.</p></li>
    /// </ul>
    pub fn action_on_timeout(&self) -> ::std::option::Option<&crate::types::DeploymentReadyAction> {
        self.action_on_timeout.as_ref()
    }
    /// <p>The number of minutes to wait before the status of a blue/green deployment is changed to Stopped if rerouting is not started manually. Applies only to the <code>STOP_DEPLOYMENT</code> option for <code>actionOnTimeout</code>.</p>
    pub fn wait_time_in_minutes(&self) -> i32 {
        self.wait_time_in_minutes
    }
}
impl DeploymentReadyOption {
    /// Creates a new builder-style object to manufacture [`DeploymentReadyOption`](crate::types::DeploymentReadyOption).
    pub fn builder() -> crate::types::builders::DeploymentReadyOptionBuilder {
        crate::types::builders::DeploymentReadyOptionBuilder::default()
    }
}

/// A builder for [`DeploymentReadyOption`](crate::types::DeploymentReadyOption).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeploymentReadyOptionBuilder {
    pub(crate) action_on_timeout: ::std::option::Option<crate::types::DeploymentReadyAction>,
    pub(crate) wait_time_in_minutes: ::std::option::Option<i32>,
}
impl DeploymentReadyOptionBuilder {
    /// <p>Information about when to reroute traffic from an original environment to a replacement environment in a blue/green deployment.</p>
    /// <ul>
    /// <li>
    /// <p>CONTINUE_DEPLOYMENT: Register new instances with the load balancer immediately after the new application revision is installed on the instances in the replacement environment.</p></li>
    /// <li>
    /// <p>STOP_DEPLOYMENT: Do not register new instances with a load balancer unless traffic rerouting is started using <code>ContinueDeployment</code>. If traffic rerouting is not started before the end of the specified wait period, the deployment status is changed to Stopped.</p></li>
    /// </ul>
    pub fn action_on_timeout(mut self, input: crate::types::DeploymentReadyAction) -> Self {
        self.action_on_timeout = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about when to reroute traffic from an original environment to a replacement environment in a blue/green deployment.</p>
    /// <ul>
    /// <li>
    /// <p>CONTINUE_DEPLOYMENT: Register new instances with the load balancer immediately after the new application revision is installed on the instances in the replacement environment.</p></li>
    /// <li>
    /// <p>STOP_DEPLOYMENT: Do not register new instances with a load balancer unless traffic rerouting is started using <code>ContinueDeployment</code>. If traffic rerouting is not started before the end of the specified wait period, the deployment status is changed to Stopped.</p></li>
    /// </ul>
    pub fn set_action_on_timeout(mut self, input: ::std::option::Option<crate::types::DeploymentReadyAction>) -> Self {
        self.action_on_timeout = input;
        self
    }
    /// <p>Information about when to reroute traffic from an original environment to a replacement environment in a blue/green deployment.</p>
    /// <ul>
    /// <li>
    /// <p>CONTINUE_DEPLOYMENT: Register new instances with the load balancer immediately after the new application revision is installed on the instances in the replacement environment.</p></li>
    /// <li>
    /// <p>STOP_DEPLOYMENT: Do not register new instances with a load balancer unless traffic rerouting is started using <code>ContinueDeployment</code>. If traffic rerouting is not started before the end of the specified wait period, the deployment status is changed to Stopped.</p></li>
    /// </ul>
    pub fn get_action_on_timeout(&self) -> &::std::option::Option<crate::types::DeploymentReadyAction> {
        &self.action_on_timeout
    }
    /// <p>The number of minutes to wait before the status of a blue/green deployment is changed to Stopped if rerouting is not started manually. Applies only to the <code>STOP_DEPLOYMENT</code> option for <code>actionOnTimeout</code>.</p>
    pub fn wait_time_in_minutes(mut self, input: i32) -> Self {
        self.wait_time_in_minutes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of minutes to wait before the status of a blue/green deployment is changed to Stopped if rerouting is not started manually. Applies only to the <code>STOP_DEPLOYMENT</code> option for <code>actionOnTimeout</code>.</p>
    pub fn set_wait_time_in_minutes(mut self, input: ::std::option::Option<i32>) -> Self {
        self.wait_time_in_minutes = input;
        self
    }
    /// <p>The number of minutes to wait before the status of a blue/green deployment is changed to Stopped if rerouting is not started manually. Applies only to the <code>STOP_DEPLOYMENT</code> option for <code>actionOnTimeout</code>.</p>
    pub fn get_wait_time_in_minutes(&self) -> &::std::option::Option<i32> {
        &self.wait_time_in_minutes
    }
    /// Consumes the builder and constructs a [`DeploymentReadyOption`](crate::types::DeploymentReadyOption).
    pub fn build(self) -> crate::types::DeploymentReadyOption {
        crate::types::DeploymentReadyOption {
            action_on_timeout: self.action_on_timeout,
            wait_time_in_minutes: self.wait_time_in_minutes.unwrap_or_default(),
        }
    }
}
