// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about a load balancer that the service uses.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsEcsServiceLoadBalancersDetails {
    /// <p>The name of the container to associate with the load balancer.</p>
    pub container_name: ::std::option::Option<::std::string::String>,
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they are launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub container_port: ::std::option::Option<i32>,
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>Only specified when using a Classic Load Balancer. For an Application Load Balancer or a Network Load Balancer, the load balancer name is omitted.</p>
    pub load_balancer_name: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>Only specified when using an Application Load Balancer or a Network Load Balancer. For a Classic Load Balancer, the target group ARN is omitted.</p>
    pub target_group_arn: ::std::option::Option<::std::string::String>,
}
impl AwsEcsServiceLoadBalancersDetails {
    /// <p>The name of the container to associate with the load balancer.</p>
    pub fn container_name(&self) -> ::std::option::Option<&str> {
        self.container_name.as_deref()
    }
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they are launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub fn container_port(&self) -> ::std::option::Option<i32> {
        self.container_port
    }
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>Only specified when using a Classic Load Balancer. For an Application Load Balancer or a Network Load Balancer, the load balancer name is omitted.</p>
    pub fn load_balancer_name(&self) -> ::std::option::Option<&str> {
        self.load_balancer_name.as_deref()
    }
    /// <p>The ARN of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>Only specified when using an Application Load Balancer or a Network Load Balancer. For a Classic Load Balancer, the target group ARN is omitted.</p>
    pub fn target_group_arn(&self) -> ::std::option::Option<&str> {
        self.target_group_arn.as_deref()
    }
}
impl AwsEcsServiceLoadBalancersDetails {
    /// Creates a new builder-style object to manufacture [`AwsEcsServiceLoadBalancersDetails`](crate::types::AwsEcsServiceLoadBalancersDetails).
    pub fn builder() -> crate::types::builders::AwsEcsServiceLoadBalancersDetailsBuilder {
        crate::types::builders::AwsEcsServiceLoadBalancersDetailsBuilder::default()
    }
}

/// A builder for [`AwsEcsServiceLoadBalancersDetails`](crate::types::AwsEcsServiceLoadBalancersDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsEcsServiceLoadBalancersDetailsBuilder {
    pub(crate) container_name: ::std::option::Option<::std::string::String>,
    pub(crate) container_port: ::std::option::Option<i32>,
    pub(crate) load_balancer_name: ::std::option::Option<::std::string::String>,
    pub(crate) target_group_arn: ::std::option::Option<::std::string::String>,
}
impl AwsEcsServiceLoadBalancersDetailsBuilder {
    /// <p>The name of the container to associate with the load balancer.</p>
    pub fn container_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container to associate with the load balancer.</p>
    pub fn set_container_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_name = input;
        self
    }
    /// <p>The name of the container to associate with the load balancer.</p>
    pub fn get_container_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_name
    }
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they are launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub fn container_port(mut self, input: i32) -> Self {
        self.container_port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they are launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub fn set_container_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.container_port = input;
        self
    }
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they are launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub fn get_container_port(&self) -> &::std::option::Option<i32> {
        &self.container_port
    }
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>Only specified when using a Classic Load Balancer. For an Application Load Balancer or a Network Load Balancer, the load balancer name is omitted.</p>
    pub fn load_balancer_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.load_balancer_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>Only specified when using a Classic Load Balancer. For an Application Load Balancer or a Network Load Balancer, the load balancer name is omitted.</p>
    pub fn set_load_balancer_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.load_balancer_name = input;
        self
    }
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>Only specified when using a Classic Load Balancer. For an Application Load Balancer or a Network Load Balancer, the load balancer name is omitted.</p>
    pub fn get_load_balancer_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.load_balancer_name
    }
    /// <p>The ARN of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>Only specified when using an Application Load Balancer or a Network Load Balancer. For a Classic Load Balancer, the target group ARN is omitted.</p>
    pub fn target_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>Only specified when using an Application Load Balancer or a Network Load Balancer. For a Classic Load Balancer, the target group ARN is omitted.</p>
    pub fn set_target_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_group_arn = input;
        self
    }
    /// <p>The ARN of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>Only specified when using an Application Load Balancer or a Network Load Balancer. For a Classic Load Balancer, the target group ARN is omitted.</p>
    pub fn get_target_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_group_arn
    }
    /// Consumes the builder and constructs a [`AwsEcsServiceLoadBalancersDetails`](crate::types::AwsEcsServiceLoadBalancersDetails).
    pub fn build(self) -> crate::types::AwsEcsServiceLoadBalancersDetails {
        crate::types::AwsEcsServiceLoadBalancersDetails {
            container_name: self.container_name,
            container_port: self.container_port,
            load_balancer_name: self.load_balancer_name,
            target_group_arn: self.target_group_arn,
        }
    }
}
