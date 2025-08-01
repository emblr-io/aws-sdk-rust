// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The load balancer configuration to use with a service or task set.</p>
/// <p>When you add, update, or remove a load balancer configuration, Amazon ECS starts a new deployment with the updated Elastic Load Balancing configuration. This causes tasks to register to and deregister from load balancers.</p>
/// <p>We recommend that you verify this on a test environment before you update the Elastic Load Balancing configuration.</p>
/// <p>A service-linked role is required for services that use multiple target groups. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/using-service-linked-roles.html">Using service-linked roles</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LoadBalancer {
    /// <p>The full Amazon Resource Name (ARN) of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>A target group ARN is only specified when using an Application Load Balancer or Network Load Balancer.</p>
    /// <p>For services using the <code>ECS</code> deployment controller, you can specify one or multiple target groups. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/register-multiple-targetgroups.html">Registering multiple target groups with a service</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p>
    /// <p>For services using the <code>CODE_DEPLOY</code> deployment controller, you're required to define two target groups for the load balancer. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-bluegreen.html">Blue/green deployment with CodeDeploy</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p><important>
    /// <p>If your service's task definition uses the <code>awsvpc</code> network mode, you must choose <code>ip</code> as the target type, not <code>instance</code>. Do this when creating your target groups because tasks that use the <code>awsvpc</code> network mode are associated with an elastic network interface, not an Amazon EC2 instance. This network mode is required for the Fargate launch type.</p>
    /// </important>
    pub target_group_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>If you are using an Application Load Balancer or a Network Load Balancer the load balancer name parameter should be omitted.</p>
    pub load_balancer_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the container (as it appears in a container definition) to associate with the load balancer.</p>
    /// <p>You need to specify the container name when configuring the target group for an Amazon ECS load balancer.</p>
    pub container_name: ::std::option::Option<::std::string::String>,
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they're launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub container_port: ::std::option::Option<i32>,
}
impl LoadBalancer {
    /// <p>The full Amazon Resource Name (ARN) of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>A target group ARN is only specified when using an Application Load Balancer or Network Load Balancer.</p>
    /// <p>For services using the <code>ECS</code> deployment controller, you can specify one or multiple target groups. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/register-multiple-targetgroups.html">Registering multiple target groups with a service</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p>
    /// <p>For services using the <code>CODE_DEPLOY</code> deployment controller, you're required to define two target groups for the load balancer. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-bluegreen.html">Blue/green deployment with CodeDeploy</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p><important>
    /// <p>If your service's task definition uses the <code>awsvpc</code> network mode, you must choose <code>ip</code> as the target type, not <code>instance</code>. Do this when creating your target groups because tasks that use the <code>awsvpc</code> network mode are associated with an elastic network interface, not an Amazon EC2 instance. This network mode is required for the Fargate launch type.</p>
    /// </important>
    pub fn target_group_arn(&self) -> ::std::option::Option<&str> {
        self.target_group_arn.as_deref()
    }
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>If you are using an Application Load Balancer or a Network Load Balancer the load balancer name parameter should be omitted.</p>
    pub fn load_balancer_name(&self) -> ::std::option::Option<&str> {
        self.load_balancer_name.as_deref()
    }
    /// <p>The name of the container (as it appears in a container definition) to associate with the load balancer.</p>
    /// <p>You need to specify the container name when configuring the target group for an Amazon ECS load balancer.</p>
    pub fn container_name(&self) -> ::std::option::Option<&str> {
        self.container_name.as_deref()
    }
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they're launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub fn container_port(&self) -> ::std::option::Option<i32> {
        self.container_port
    }
}
impl LoadBalancer {
    /// Creates a new builder-style object to manufacture [`LoadBalancer`](crate::types::LoadBalancer).
    pub fn builder() -> crate::types::builders::LoadBalancerBuilder {
        crate::types::builders::LoadBalancerBuilder::default()
    }
}

/// A builder for [`LoadBalancer`](crate::types::LoadBalancer).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LoadBalancerBuilder {
    pub(crate) target_group_arn: ::std::option::Option<::std::string::String>,
    pub(crate) load_balancer_name: ::std::option::Option<::std::string::String>,
    pub(crate) container_name: ::std::option::Option<::std::string::String>,
    pub(crate) container_port: ::std::option::Option<i32>,
}
impl LoadBalancerBuilder {
    /// <p>The full Amazon Resource Name (ARN) of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>A target group ARN is only specified when using an Application Load Balancer or Network Load Balancer.</p>
    /// <p>For services using the <code>ECS</code> deployment controller, you can specify one or multiple target groups. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/register-multiple-targetgroups.html">Registering multiple target groups with a service</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p>
    /// <p>For services using the <code>CODE_DEPLOY</code> deployment controller, you're required to define two target groups for the load balancer. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-bluegreen.html">Blue/green deployment with CodeDeploy</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p><important>
    /// <p>If your service's task definition uses the <code>awsvpc</code> network mode, you must choose <code>ip</code> as the target type, not <code>instance</code>. Do this when creating your target groups because tasks that use the <code>awsvpc</code> network mode are associated with an elastic network interface, not an Amazon EC2 instance. This network mode is required for the Fargate launch type.</p>
    /// </important>
    pub fn target_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The full Amazon Resource Name (ARN) of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>A target group ARN is only specified when using an Application Load Balancer or Network Load Balancer.</p>
    /// <p>For services using the <code>ECS</code> deployment controller, you can specify one or multiple target groups. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/register-multiple-targetgroups.html">Registering multiple target groups with a service</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p>
    /// <p>For services using the <code>CODE_DEPLOY</code> deployment controller, you're required to define two target groups for the load balancer. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-bluegreen.html">Blue/green deployment with CodeDeploy</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p><important>
    /// <p>If your service's task definition uses the <code>awsvpc</code> network mode, you must choose <code>ip</code> as the target type, not <code>instance</code>. Do this when creating your target groups because tasks that use the <code>awsvpc</code> network mode are associated with an elastic network interface, not an Amazon EC2 instance. This network mode is required for the Fargate launch type.</p>
    /// </important>
    pub fn set_target_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_group_arn = input;
        self
    }
    /// <p>The full Amazon Resource Name (ARN) of the Elastic Load Balancing target group or groups associated with a service or task set.</p>
    /// <p>A target group ARN is only specified when using an Application Load Balancer or Network Load Balancer.</p>
    /// <p>For services using the <code>ECS</code> deployment controller, you can specify one or multiple target groups. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/register-multiple-targetgroups.html">Registering multiple target groups with a service</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p>
    /// <p>For services using the <code>CODE_DEPLOY</code> deployment controller, you're required to define two target groups for the load balancer. For more information, see <a href="https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-type-bluegreen.html">Blue/green deployment with CodeDeploy</a> in the <i>Amazon Elastic Container Service Developer Guide</i>.</p><important>
    /// <p>If your service's task definition uses the <code>awsvpc</code> network mode, you must choose <code>ip</code> as the target type, not <code>instance</code>. Do this when creating your target groups because tasks that use the <code>awsvpc</code> network mode are associated with an elastic network interface, not an Amazon EC2 instance. This network mode is required for the Fargate launch type.</p>
    /// </important>
    pub fn get_target_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_group_arn
    }
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>If you are using an Application Load Balancer or a Network Load Balancer the load balancer name parameter should be omitted.</p>
    pub fn load_balancer_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.load_balancer_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>If you are using an Application Load Balancer or a Network Load Balancer the load balancer name parameter should be omitted.</p>
    pub fn set_load_balancer_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.load_balancer_name = input;
        self
    }
    /// <p>The name of the load balancer to associate with the Amazon ECS service or task set.</p>
    /// <p>If you are using an Application Load Balancer or a Network Load Balancer the load balancer name parameter should be omitted.</p>
    pub fn get_load_balancer_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.load_balancer_name
    }
    /// <p>The name of the container (as it appears in a container definition) to associate with the load balancer.</p>
    /// <p>You need to specify the container name when configuring the target group for an Amazon ECS load balancer.</p>
    pub fn container_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.container_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the container (as it appears in a container definition) to associate with the load balancer.</p>
    /// <p>You need to specify the container name when configuring the target group for an Amazon ECS load balancer.</p>
    pub fn set_container_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.container_name = input;
        self
    }
    /// <p>The name of the container (as it appears in a container definition) to associate with the load balancer.</p>
    /// <p>You need to specify the container name when configuring the target group for an Amazon ECS load balancer.</p>
    pub fn get_container_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.container_name
    }
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they're launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub fn container_port(mut self, input: i32) -> Self {
        self.container_port = ::std::option::Option::Some(input);
        self
    }
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they're launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub fn set_container_port(mut self, input: ::std::option::Option<i32>) -> Self {
        self.container_port = input;
        self
    }
    /// <p>The port on the container to associate with the load balancer. This port must correspond to a <code>containerPort</code> in the task definition the tasks in the service are using. For tasks that use the EC2 launch type, the container instance they're launched on must allow ingress traffic on the <code>hostPort</code> of the port mapping.</p>
    pub fn get_container_port(&self) -> &::std::option::Option<i32> {
        &self.container_port
    }
    /// Consumes the builder and constructs a [`LoadBalancer`](crate::types::LoadBalancer).
    pub fn build(self) -> crate::types::LoadBalancer {
        crate::types::LoadBalancer {
            target_group_arn: self.target_group_arn,
            load_balancer_name: self.load_balancer_name,
            container_name: self.container_name,
            container_port: self.container_port,
        }
    }
}
