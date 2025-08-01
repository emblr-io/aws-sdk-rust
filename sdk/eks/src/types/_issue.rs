// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An object representing an issue with an Amazon EKS resource.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Issue {
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>AccessDenied</b>: Amazon EKS or one or more of your managed nodes is failing to authenticate or authorize with your Kubernetes cluster API server.</p></li>
    /// <li>
    /// <p><b>AsgInstanceLaunchFailures</b>: Your Auto Scaling group is experiencing failures while attempting to launch instances.</p></li>
    /// <li>
    /// <p><b>AutoScalingGroupNotFound</b>: We couldn't find the Auto Scaling group associated with the managed node group. You may be able to recreate an Auto Scaling group with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>ClusterUnreachable</b>: Amazon EKS or one or more of your managed nodes is unable to to communicate with your Kubernetes cluster API server. This can happen if there are network disruptions or if API servers are timing out processing requests.</p></li>
    /// <li>
    /// <p><b>Ec2InstanceTypeDoesNotExist</b>: One or more of the supplied Amazon EC2 instance types do not exist. Amazon EKS checked for the instance types that you provided in this Amazon Web Services Region, and one or more aren't available.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateNotFound</b>: We couldn't find the Amazon EC2 launch template for your managed node group. You may be able to recreate a launch template with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateVersionMismatch</b>: The Amazon EC2 launch template version for your managed node group does not match the version that Amazon EKS created. You may be able to revert to the version that Amazon EKS created to recover.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupDeletionFailure</b>: We could not delete the remote access security group for your managed node group. Remove any dependencies from the security group.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupNotFound</b>: We couldn't find the cluster security group for the cluster. You must recreate your cluster.</p></li>
    /// <li>
    /// <p><b>Ec2SubnetInvalidConfiguration</b>: One or more Amazon EC2 subnets specified for a node group do not automatically assign public IP addresses to instances launched into it. If you want your instances to be assigned a public IP address, then you need to enable the <code>auto-assign public IP address</code> setting for the subnet. See <a href="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html#subnet-public-ip">Modifying the public <code>IPv4</code> addressing attribute for your subnet</a> in the <i>Amazon VPC User Guide</i>.</p></li>
    /// <li>
    /// <p><b>IamInstanceProfileNotFound</b>: We couldn't find the IAM instance profile for your managed node group. You may be able to recreate an instance profile with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>IamNodeRoleNotFound</b>: We couldn't find the IAM role for your managed node group. You may be able to recreate an IAM role with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>InstanceLimitExceeded</b>: Your Amazon Web Services account is unable to launch any more instances of the specified instance type. You may be able to request an Amazon EC2 instance limit increase to recover.</p></li>
    /// <li>
    /// <p><b>InsufficientFreeAddresses</b>: One or more of the subnets associated with your managed node group does not have enough available IP addresses for new nodes.</p></li>
    /// <li>
    /// <p><b>InternalFailure</b>: These errors are usually caused by an Amazon EKS server-side issue.</p></li>
    /// <li>
    /// <p><b>NodeCreationFailure</b>: Your launched instances are unable to register with your Amazon EKS cluster. Common causes of this failure are insufficient <a href="https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html">node IAM role</a> permissions or lack of outbound internet access for the nodes.</p></li>
    /// </ul>
    pub code: ::std::option::Option<crate::types::NodegroupIssueCode>,
    /// <p>The error message associated with the issue.</p>
    pub message: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services resources that are afflicted by this issue.</p>
    pub resource_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl Issue {
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>AccessDenied</b>: Amazon EKS or one or more of your managed nodes is failing to authenticate or authorize with your Kubernetes cluster API server.</p></li>
    /// <li>
    /// <p><b>AsgInstanceLaunchFailures</b>: Your Auto Scaling group is experiencing failures while attempting to launch instances.</p></li>
    /// <li>
    /// <p><b>AutoScalingGroupNotFound</b>: We couldn't find the Auto Scaling group associated with the managed node group. You may be able to recreate an Auto Scaling group with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>ClusterUnreachable</b>: Amazon EKS or one or more of your managed nodes is unable to to communicate with your Kubernetes cluster API server. This can happen if there are network disruptions or if API servers are timing out processing requests.</p></li>
    /// <li>
    /// <p><b>Ec2InstanceTypeDoesNotExist</b>: One or more of the supplied Amazon EC2 instance types do not exist. Amazon EKS checked for the instance types that you provided in this Amazon Web Services Region, and one or more aren't available.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateNotFound</b>: We couldn't find the Amazon EC2 launch template for your managed node group. You may be able to recreate a launch template with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateVersionMismatch</b>: The Amazon EC2 launch template version for your managed node group does not match the version that Amazon EKS created. You may be able to revert to the version that Amazon EKS created to recover.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupDeletionFailure</b>: We could not delete the remote access security group for your managed node group. Remove any dependencies from the security group.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupNotFound</b>: We couldn't find the cluster security group for the cluster. You must recreate your cluster.</p></li>
    /// <li>
    /// <p><b>Ec2SubnetInvalidConfiguration</b>: One or more Amazon EC2 subnets specified for a node group do not automatically assign public IP addresses to instances launched into it. If you want your instances to be assigned a public IP address, then you need to enable the <code>auto-assign public IP address</code> setting for the subnet. See <a href="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html#subnet-public-ip">Modifying the public <code>IPv4</code> addressing attribute for your subnet</a> in the <i>Amazon VPC User Guide</i>.</p></li>
    /// <li>
    /// <p><b>IamInstanceProfileNotFound</b>: We couldn't find the IAM instance profile for your managed node group. You may be able to recreate an instance profile with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>IamNodeRoleNotFound</b>: We couldn't find the IAM role for your managed node group. You may be able to recreate an IAM role with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>InstanceLimitExceeded</b>: Your Amazon Web Services account is unable to launch any more instances of the specified instance type. You may be able to request an Amazon EC2 instance limit increase to recover.</p></li>
    /// <li>
    /// <p><b>InsufficientFreeAddresses</b>: One or more of the subnets associated with your managed node group does not have enough available IP addresses for new nodes.</p></li>
    /// <li>
    /// <p><b>InternalFailure</b>: These errors are usually caused by an Amazon EKS server-side issue.</p></li>
    /// <li>
    /// <p><b>NodeCreationFailure</b>: Your launched instances are unable to register with your Amazon EKS cluster. Common causes of this failure are insufficient <a href="https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html">node IAM role</a> permissions or lack of outbound internet access for the nodes.</p></li>
    /// </ul>
    pub fn code(&self) -> ::std::option::Option<&crate::types::NodegroupIssueCode> {
        self.code.as_ref()
    }
    /// <p>The error message associated with the issue.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
    /// <p>The Amazon Web Services resources that are afflicted by this issue.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_ids.is_none()`.
    pub fn resource_ids(&self) -> &[::std::string::String] {
        self.resource_ids.as_deref().unwrap_or_default()
    }
}
impl Issue {
    /// Creates a new builder-style object to manufacture [`Issue`](crate::types::Issue).
    pub fn builder() -> crate::types::builders::IssueBuilder {
        crate::types::builders::IssueBuilder::default()
    }
}

/// A builder for [`Issue`](crate::types::Issue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IssueBuilder {
    pub(crate) code: ::std::option::Option<crate::types::NodegroupIssueCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
    pub(crate) resource_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl IssueBuilder {
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>AccessDenied</b>: Amazon EKS or one or more of your managed nodes is failing to authenticate or authorize with your Kubernetes cluster API server.</p></li>
    /// <li>
    /// <p><b>AsgInstanceLaunchFailures</b>: Your Auto Scaling group is experiencing failures while attempting to launch instances.</p></li>
    /// <li>
    /// <p><b>AutoScalingGroupNotFound</b>: We couldn't find the Auto Scaling group associated with the managed node group. You may be able to recreate an Auto Scaling group with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>ClusterUnreachable</b>: Amazon EKS or one or more of your managed nodes is unable to to communicate with your Kubernetes cluster API server. This can happen if there are network disruptions or if API servers are timing out processing requests.</p></li>
    /// <li>
    /// <p><b>Ec2InstanceTypeDoesNotExist</b>: One or more of the supplied Amazon EC2 instance types do not exist. Amazon EKS checked for the instance types that you provided in this Amazon Web Services Region, and one or more aren't available.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateNotFound</b>: We couldn't find the Amazon EC2 launch template for your managed node group. You may be able to recreate a launch template with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateVersionMismatch</b>: The Amazon EC2 launch template version for your managed node group does not match the version that Amazon EKS created. You may be able to revert to the version that Amazon EKS created to recover.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupDeletionFailure</b>: We could not delete the remote access security group for your managed node group. Remove any dependencies from the security group.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupNotFound</b>: We couldn't find the cluster security group for the cluster. You must recreate your cluster.</p></li>
    /// <li>
    /// <p><b>Ec2SubnetInvalidConfiguration</b>: One or more Amazon EC2 subnets specified for a node group do not automatically assign public IP addresses to instances launched into it. If you want your instances to be assigned a public IP address, then you need to enable the <code>auto-assign public IP address</code> setting for the subnet. See <a href="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html#subnet-public-ip">Modifying the public <code>IPv4</code> addressing attribute for your subnet</a> in the <i>Amazon VPC User Guide</i>.</p></li>
    /// <li>
    /// <p><b>IamInstanceProfileNotFound</b>: We couldn't find the IAM instance profile for your managed node group. You may be able to recreate an instance profile with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>IamNodeRoleNotFound</b>: We couldn't find the IAM role for your managed node group. You may be able to recreate an IAM role with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>InstanceLimitExceeded</b>: Your Amazon Web Services account is unable to launch any more instances of the specified instance type. You may be able to request an Amazon EC2 instance limit increase to recover.</p></li>
    /// <li>
    /// <p><b>InsufficientFreeAddresses</b>: One or more of the subnets associated with your managed node group does not have enough available IP addresses for new nodes.</p></li>
    /// <li>
    /// <p><b>InternalFailure</b>: These errors are usually caused by an Amazon EKS server-side issue.</p></li>
    /// <li>
    /// <p><b>NodeCreationFailure</b>: Your launched instances are unable to register with your Amazon EKS cluster. Common causes of this failure are insufficient <a href="https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html">node IAM role</a> permissions or lack of outbound internet access for the nodes.</p></li>
    /// </ul>
    pub fn code(mut self, input: crate::types::NodegroupIssueCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>AccessDenied</b>: Amazon EKS or one or more of your managed nodes is failing to authenticate or authorize with your Kubernetes cluster API server.</p></li>
    /// <li>
    /// <p><b>AsgInstanceLaunchFailures</b>: Your Auto Scaling group is experiencing failures while attempting to launch instances.</p></li>
    /// <li>
    /// <p><b>AutoScalingGroupNotFound</b>: We couldn't find the Auto Scaling group associated with the managed node group. You may be able to recreate an Auto Scaling group with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>ClusterUnreachable</b>: Amazon EKS or one or more of your managed nodes is unable to to communicate with your Kubernetes cluster API server. This can happen if there are network disruptions or if API servers are timing out processing requests.</p></li>
    /// <li>
    /// <p><b>Ec2InstanceTypeDoesNotExist</b>: One or more of the supplied Amazon EC2 instance types do not exist. Amazon EKS checked for the instance types that you provided in this Amazon Web Services Region, and one or more aren't available.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateNotFound</b>: We couldn't find the Amazon EC2 launch template for your managed node group. You may be able to recreate a launch template with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateVersionMismatch</b>: The Amazon EC2 launch template version for your managed node group does not match the version that Amazon EKS created. You may be able to revert to the version that Amazon EKS created to recover.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupDeletionFailure</b>: We could not delete the remote access security group for your managed node group. Remove any dependencies from the security group.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupNotFound</b>: We couldn't find the cluster security group for the cluster. You must recreate your cluster.</p></li>
    /// <li>
    /// <p><b>Ec2SubnetInvalidConfiguration</b>: One or more Amazon EC2 subnets specified for a node group do not automatically assign public IP addresses to instances launched into it. If you want your instances to be assigned a public IP address, then you need to enable the <code>auto-assign public IP address</code> setting for the subnet. See <a href="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html#subnet-public-ip">Modifying the public <code>IPv4</code> addressing attribute for your subnet</a> in the <i>Amazon VPC User Guide</i>.</p></li>
    /// <li>
    /// <p><b>IamInstanceProfileNotFound</b>: We couldn't find the IAM instance profile for your managed node group. You may be able to recreate an instance profile with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>IamNodeRoleNotFound</b>: We couldn't find the IAM role for your managed node group. You may be able to recreate an IAM role with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>InstanceLimitExceeded</b>: Your Amazon Web Services account is unable to launch any more instances of the specified instance type. You may be able to request an Amazon EC2 instance limit increase to recover.</p></li>
    /// <li>
    /// <p><b>InsufficientFreeAddresses</b>: One or more of the subnets associated with your managed node group does not have enough available IP addresses for new nodes.</p></li>
    /// <li>
    /// <p><b>InternalFailure</b>: These errors are usually caused by an Amazon EKS server-side issue.</p></li>
    /// <li>
    /// <p><b>NodeCreationFailure</b>: Your launched instances are unable to register with your Amazon EKS cluster. Common causes of this failure are insufficient <a href="https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html">node IAM role</a> permissions or lack of outbound internet access for the nodes.</p></li>
    /// </ul>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::NodegroupIssueCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>A brief description of the error.</p>
    /// <ul>
    /// <li>
    /// <p><b>AccessDenied</b>: Amazon EKS or one or more of your managed nodes is failing to authenticate or authorize with your Kubernetes cluster API server.</p></li>
    /// <li>
    /// <p><b>AsgInstanceLaunchFailures</b>: Your Auto Scaling group is experiencing failures while attempting to launch instances.</p></li>
    /// <li>
    /// <p><b>AutoScalingGroupNotFound</b>: We couldn't find the Auto Scaling group associated with the managed node group. You may be able to recreate an Auto Scaling group with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>ClusterUnreachable</b>: Amazon EKS or one or more of your managed nodes is unable to to communicate with your Kubernetes cluster API server. This can happen if there are network disruptions or if API servers are timing out processing requests.</p></li>
    /// <li>
    /// <p><b>Ec2InstanceTypeDoesNotExist</b>: One or more of the supplied Amazon EC2 instance types do not exist. Amazon EKS checked for the instance types that you provided in this Amazon Web Services Region, and one or more aren't available.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateNotFound</b>: We couldn't find the Amazon EC2 launch template for your managed node group. You may be able to recreate a launch template with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>Ec2LaunchTemplateVersionMismatch</b>: The Amazon EC2 launch template version for your managed node group does not match the version that Amazon EKS created. You may be able to revert to the version that Amazon EKS created to recover.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupDeletionFailure</b>: We could not delete the remote access security group for your managed node group. Remove any dependencies from the security group.</p></li>
    /// <li>
    /// <p><b>Ec2SecurityGroupNotFound</b>: We couldn't find the cluster security group for the cluster. You must recreate your cluster.</p></li>
    /// <li>
    /// <p><b>Ec2SubnetInvalidConfiguration</b>: One or more Amazon EC2 subnets specified for a node group do not automatically assign public IP addresses to instances launched into it. If you want your instances to be assigned a public IP address, then you need to enable the <code>auto-assign public IP address</code> setting for the subnet. See <a href="https://docs.aws.amazon.com/vpc/latest/userguide/vpc-ip-addressing.html#subnet-public-ip">Modifying the public <code>IPv4</code> addressing attribute for your subnet</a> in the <i>Amazon VPC User Guide</i>.</p></li>
    /// <li>
    /// <p><b>IamInstanceProfileNotFound</b>: We couldn't find the IAM instance profile for your managed node group. You may be able to recreate an instance profile with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>IamNodeRoleNotFound</b>: We couldn't find the IAM role for your managed node group. You may be able to recreate an IAM role with the same settings to recover.</p></li>
    /// <li>
    /// <p><b>InstanceLimitExceeded</b>: Your Amazon Web Services account is unable to launch any more instances of the specified instance type. You may be able to request an Amazon EC2 instance limit increase to recover.</p></li>
    /// <li>
    /// <p><b>InsufficientFreeAddresses</b>: One or more of the subnets associated with your managed node group does not have enough available IP addresses for new nodes.</p></li>
    /// <li>
    /// <p><b>InternalFailure</b>: These errors are usually caused by an Amazon EKS server-side issue.</p></li>
    /// <li>
    /// <p><b>NodeCreationFailure</b>: Your launched instances are unable to register with your Amazon EKS cluster. Common causes of this failure are insufficient <a href="https://docs.aws.amazon.com/eks/latest/userguide/create-node-role.html">node IAM role</a> permissions or lack of outbound internet access for the nodes.</p></li>
    /// </ul>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::NodegroupIssueCode> {
        &self.code
    }
    /// <p>The error message associated with the issue.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The error message associated with the issue.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The error message associated with the issue.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Appends an item to `resource_ids`.
    ///
    /// To override the contents of this collection use [`set_resource_ids`](Self::set_resource_ids).
    ///
    /// <p>The Amazon Web Services resources that are afflicted by this issue.</p>
    pub fn resource_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_ids.unwrap_or_default();
        v.push(input.into());
        self.resource_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The Amazon Web Services resources that are afflicted by this issue.</p>
    pub fn set_resource_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_ids = input;
        self
    }
    /// <p>The Amazon Web Services resources that are afflicted by this issue.</p>
    pub fn get_resource_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_ids
    }
    /// Consumes the builder and constructs a [`Issue`](crate::types::Issue).
    pub fn build(self) -> crate::types::Issue {
        crate::types::Issue {
            code: self.code,
            message: self.message,
            resource_ids: self.resource_ids,
        }
    }
}
