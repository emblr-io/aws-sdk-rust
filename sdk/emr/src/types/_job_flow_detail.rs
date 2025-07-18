// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A description of a cluster (job flow).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JobFlowDetail {
    /// <p>The job flow identifier.</p>
    pub job_flow_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the job flow.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The location in Amazon S3 where log files for the job are stored.</p>
    pub log_uri: ::std::option::Option<::std::string::String>,
    /// <p>The KMS key used for encrypting log files. This attribute is only available with Amazon EMR 5.30.0 and later, excluding 6.0.0.</p>
    pub log_encryption_kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>Applies only to Amazon EMR AMI versions 3.x and 2.x. For Amazon EMR releases 4.0 and later, <code>ReleaseLabel</code> is used. To specify a custom AMI, use <code>CustomAmiID</code>.</p>
    pub ami_version: ::std::option::Option<::std::string::String>,
    /// <p>Describes the execution status of the job flow.</p>
    pub execution_status_detail: ::std::option::Option<crate::types::JobFlowExecutionStatusDetail>,
    /// <p>Describes the Amazon EC2 instances of the job flow.</p>
    pub instances: ::std::option::Option<crate::types::JobFlowInstancesDetail>,
    /// <p>A list of steps run by the job flow.</p>
    pub steps: ::std::option::Option<::std::vec::Vec<crate::types::StepDetail>>,
    /// <p>A list of the bootstrap actions run by the job flow.</p>
    pub bootstrap_actions: ::std::option::Option<::std::vec::Vec<crate::types::BootstrapActionDetail>>,
    /// <p>A list of strings set by third-party software when the job flow is launched. If you are not using third-party software to manage the job flow, this value is empty.</p>
    pub supported_products: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Indicates whether the cluster is visible to IAM principals in the Amazon Web Services account associated with the cluster. When <code>true</code>, IAM principals in the Amazon Web Services account can perform Amazon EMR cluster actions that their IAM policies allow. When <code>false</code>, only the IAM principal that created the cluster and the Amazon Web Services account root user can perform Amazon EMR actions, regardless of IAM permissions policies attached to other IAM principals.</p>
    /// <p>The default value is <code>true</code> if a value is not provided when creating a cluster using the Amazon EMR API <code>RunJobFlow</code> command, the CLI <a href="https://docs.aws.amazon.com/cli/latest/reference/emr/create-cluster.html">create-cluster</a> command, or the Amazon Web Services Management Console.</p>
    pub visible_to_all_users: ::std::option::Option<bool>,
    /// <p>The IAM role that was specified when the job flow was launched. The Amazon EC2 instances of the job flow assume this role.</p>
    pub job_flow_role: ::std::option::Option<::std::string::String>,
    /// <p>The IAM role that is assumed by the Amazon EMR service to access Amazon Web Services resources on your behalf.</p>
    pub service_role: ::std::option::Option<::std::string::String>,
    /// <p>An IAM role for automatic scaling policies. The default role is <code>EMR_AutoScaling_DefaultRole</code>. The IAM role provides a way for the automatic scaling feature to get the required permissions it needs to launch and terminate Amazon EC2 instances in an instance group.</p>
    pub auto_scaling_role: ::std::option::Option<::std::string::String>,
    /// <p>The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized. <code>TERMINATE_AT_INSTANCE_HOUR</code> indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. <code>TERMINATE_AT_TASK_COMPLETION</code> indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. <code>TERMINATE_AT_TASK_COMPLETION</code> available only in Amazon EMR releases 4.1.0 and later, and is the default for releases of Amazon EMR earlier than 5.1.0.</p>
    pub scale_down_behavior: ::std::option::Option<crate::types::ScaleDownBehavior>,
}
impl JobFlowDetail {
    /// <p>The job flow identifier.</p>
    pub fn job_flow_id(&self) -> ::std::option::Option<&str> {
        self.job_flow_id.as_deref()
    }
    /// <p>The name of the job flow.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The location in Amazon S3 where log files for the job are stored.</p>
    pub fn log_uri(&self) -> ::std::option::Option<&str> {
        self.log_uri.as_deref()
    }
    /// <p>The KMS key used for encrypting log files. This attribute is only available with Amazon EMR 5.30.0 and later, excluding 6.0.0.</p>
    pub fn log_encryption_kms_key_id(&self) -> ::std::option::Option<&str> {
        self.log_encryption_kms_key_id.as_deref()
    }
    /// <p>Applies only to Amazon EMR AMI versions 3.x and 2.x. For Amazon EMR releases 4.0 and later, <code>ReleaseLabel</code> is used. To specify a custom AMI, use <code>CustomAmiID</code>.</p>
    pub fn ami_version(&self) -> ::std::option::Option<&str> {
        self.ami_version.as_deref()
    }
    /// <p>Describes the execution status of the job flow.</p>
    pub fn execution_status_detail(&self) -> ::std::option::Option<&crate::types::JobFlowExecutionStatusDetail> {
        self.execution_status_detail.as_ref()
    }
    /// <p>Describes the Amazon EC2 instances of the job flow.</p>
    pub fn instances(&self) -> ::std::option::Option<&crate::types::JobFlowInstancesDetail> {
        self.instances.as_ref()
    }
    /// <p>A list of steps run by the job flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.steps.is_none()`.
    pub fn steps(&self) -> &[crate::types::StepDetail] {
        self.steps.as_deref().unwrap_or_default()
    }
    /// <p>A list of the bootstrap actions run by the job flow.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.bootstrap_actions.is_none()`.
    pub fn bootstrap_actions(&self) -> &[crate::types::BootstrapActionDetail] {
        self.bootstrap_actions.as_deref().unwrap_or_default()
    }
    /// <p>A list of strings set by third-party software when the job flow is launched. If you are not using third-party software to manage the job flow, this value is empty.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.supported_products.is_none()`.
    pub fn supported_products(&self) -> &[::std::string::String] {
        self.supported_products.as_deref().unwrap_or_default()
    }
    /// <p>Indicates whether the cluster is visible to IAM principals in the Amazon Web Services account associated with the cluster. When <code>true</code>, IAM principals in the Amazon Web Services account can perform Amazon EMR cluster actions that their IAM policies allow. When <code>false</code>, only the IAM principal that created the cluster and the Amazon Web Services account root user can perform Amazon EMR actions, regardless of IAM permissions policies attached to other IAM principals.</p>
    /// <p>The default value is <code>true</code> if a value is not provided when creating a cluster using the Amazon EMR API <code>RunJobFlow</code> command, the CLI <a href="https://docs.aws.amazon.com/cli/latest/reference/emr/create-cluster.html">create-cluster</a> command, or the Amazon Web Services Management Console.</p>
    pub fn visible_to_all_users(&self) -> ::std::option::Option<bool> {
        self.visible_to_all_users
    }
    /// <p>The IAM role that was specified when the job flow was launched. The Amazon EC2 instances of the job flow assume this role.</p>
    pub fn job_flow_role(&self) -> ::std::option::Option<&str> {
        self.job_flow_role.as_deref()
    }
    /// <p>The IAM role that is assumed by the Amazon EMR service to access Amazon Web Services resources on your behalf.</p>
    pub fn service_role(&self) -> ::std::option::Option<&str> {
        self.service_role.as_deref()
    }
    /// <p>An IAM role for automatic scaling policies. The default role is <code>EMR_AutoScaling_DefaultRole</code>. The IAM role provides a way for the automatic scaling feature to get the required permissions it needs to launch and terminate Amazon EC2 instances in an instance group.</p>
    pub fn auto_scaling_role(&self) -> ::std::option::Option<&str> {
        self.auto_scaling_role.as_deref()
    }
    /// <p>The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized. <code>TERMINATE_AT_INSTANCE_HOUR</code> indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. <code>TERMINATE_AT_TASK_COMPLETION</code> indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. <code>TERMINATE_AT_TASK_COMPLETION</code> available only in Amazon EMR releases 4.1.0 and later, and is the default for releases of Amazon EMR earlier than 5.1.0.</p>
    pub fn scale_down_behavior(&self) -> ::std::option::Option<&crate::types::ScaleDownBehavior> {
        self.scale_down_behavior.as_ref()
    }
}
impl JobFlowDetail {
    /// Creates a new builder-style object to manufacture [`JobFlowDetail`](crate::types::JobFlowDetail).
    pub fn builder() -> crate::types::builders::JobFlowDetailBuilder {
        crate::types::builders::JobFlowDetailBuilder::default()
    }
}

/// A builder for [`JobFlowDetail`](crate::types::JobFlowDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JobFlowDetailBuilder {
    pub(crate) job_flow_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) log_uri: ::std::option::Option<::std::string::String>,
    pub(crate) log_encryption_kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) ami_version: ::std::option::Option<::std::string::String>,
    pub(crate) execution_status_detail: ::std::option::Option<crate::types::JobFlowExecutionStatusDetail>,
    pub(crate) instances: ::std::option::Option<crate::types::JobFlowInstancesDetail>,
    pub(crate) steps: ::std::option::Option<::std::vec::Vec<crate::types::StepDetail>>,
    pub(crate) bootstrap_actions: ::std::option::Option<::std::vec::Vec<crate::types::BootstrapActionDetail>>,
    pub(crate) supported_products: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) visible_to_all_users: ::std::option::Option<bool>,
    pub(crate) job_flow_role: ::std::option::Option<::std::string::String>,
    pub(crate) service_role: ::std::option::Option<::std::string::String>,
    pub(crate) auto_scaling_role: ::std::option::Option<::std::string::String>,
    pub(crate) scale_down_behavior: ::std::option::Option<crate::types::ScaleDownBehavior>,
}
impl JobFlowDetailBuilder {
    /// <p>The job flow identifier.</p>
    /// This field is required.
    pub fn job_flow_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_flow_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The job flow identifier.</p>
    pub fn set_job_flow_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_flow_id = input;
        self
    }
    /// <p>The job flow identifier.</p>
    pub fn get_job_flow_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_flow_id
    }
    /// <p>The name of the job flow.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the job flow.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the job flow.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The location in Amazon S3 where log files for the job are stored.</p>
    pub fn log_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The location in Amazon S3 where log files for the job are stored.</p>
    pub fn set_log_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_uri = input;
        self
    }
    /// <p>The location in Amazon S3 where log files for the job are stored.</p>
    pub fn get_log_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_uri
    }
    /// <p>The KMS key used for encrypting log files. This attribute is only available with Amazon EMR 5.30.0 and later, excluding 6.0.0.</p>
    pub fn log_encryption_kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_encryption_kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The KMS key used for encrypting log files. This attribute is only available with Amazon EMR 5.30.0 and later, excluding 6.0.0.</p>
    pub fn set_log_encryption_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_encryption_kms_key_id = input;
        self
    }
    /// <p>The KMS key used for encrypting log files. This attribute is only available with Amazon EMR 5.30.0 and later, excluding 6.0.0.</p>
    pub fn get_log_encryption_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_encryption_kms_key_id
    }
    /// <p>Applies only to Amazon EMR AMI versions 3.x and 2.x. For Amazon EMR releases 4.0 and later, <code>ReleaseLabel</code> is used. To specify a custom AMI, use <code>CustomAmiID</code>.</p>
    pub fn ami_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ami_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Applies only to Amazon EMR AMI versions 3.x and 2.x. For Amazon EMR releases 4.0 and later, <code>ReleaseLabel</code> is used. To specify a custom AMI, use <code>CustomAmiID</code>.</p>
    pub fn set_ami_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ami_version = input;
        self
    }
    /// <p>Applies only to Amazon EMR AMI versions 3.x and 2.x. For Amazon EMR releases 4.0 and later, <code>ReleaseLabel</code> is used. To specify a custom AMI, use <code>CustomAmiID</code>.</p>
    pub fn get_ami_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.ami_version
    }
    /// <p>Describes the execution status of the job flow.</p>
    /// This field is required.
    pub fn execution_status_detail(mut self, input: crate::types::JobFlowExecutionStatusDetail) -> Self {
        self.execution_status_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the execution status of the job flow.</p>
    pub fn set_execution_status_detail(mut self, input: ::std::option::Option<crate::types::JobFlowExecutionStatusDetail>) -> Self {
        self.execution_status_detail = input;
        self
    }
    /// <p>Describes the execution status of the job flow.</p>
    pub fn get_execution_status_detail(&self) -> &::std::option::Option<crate::types::JobFlowExecutionStatusDetail> {
        &self.execution_status_detail
    }
    /// <p>Describes the Amazon EC2 instances of the job flow.</p>
    /// This field is required.
    pub fn instances(mut self, input: crate::types::JobFlowInstancesDetail) -> Self {
        self.instances = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the Amazon EC2 instances of the job flow.</p>
    pub fn set_instances(mut self, input: ::std::option::Option<crate::types::JobFlowInstancesDetail>) -> Self {
        self.instances = input;
        self
    }
    /// <p>Describes the Amazon EC2 instances of the job flow.</p>
    pub fn get_instances(&self) -> &::std::option::Option<crate::types::JobFlowInstancesDetail> {
        &self.instances
    }
    /// Appends an item to `steps`.
    ///
    /// To override the contents of this collection use [`set_steps`](Self::set_steps).
    ///
    /// <p>A list of steps run by the job flow.</p>
    pub fn steps(mut self, input: crate::types::StepDetail) -> Self {
        let mut v = self.steps.unwrap_or_default();
        v.push(input);
        self.steps = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of steps run by the job flow.</p>
    pub fn set_steps(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::StepDetail>>) -> Self {
        self.steps = input;
        self
    }
    /// <p>A list of steps run by the job flow.</p>
    pub fn get_steps(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::StepDetail>> {
        &self.steps
    }
    /// Appends an item to `bootstrap_actions`.
    ///
    /// To override the contents of this collection use [`set_bootstrap_actions`](Self::set_bootstrap_actions).
    ///
    /// <p>A list of the bootstrap actions run by the job flow.</p>
    pub fn bootstrap_actions(mut self, input: crate::types::BootstrapActionDetail) -> Self {
        let mut v = self.bootstrap_actions.unwrap_or_default();
        v.push(input);
        self.bootstrap_actions = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of the bootstrap actions run by the job flow.</p>
    pub fn set_bootstrap_actions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BootstrapActionDetail>>) -> Self {
        self.bootstrap_actions = input;
        self
    }
    /// <p>A list of the bootstrap actions run by the job flow.</p>
    pub fn get_bootstrap_actions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BootstrapActionDetail>> {
        &self.bootstrap_actions
    }
    /// Appends an item to `supported_products`.
    ///
    /// To override the contents of this collection use [`set_supported_products`](Self::set_supported_products).
    ///
    /// <p>A list of strings set by third-party software when the job flow is launched. If you are not using third-party software to manage the job flow, this value is empty.</p>
    pub fn supported_products(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.supported_products.unwrap_or_default();
        v.push(input.into());
        self.supported_products = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of strings set by third-party software when the job flow is launched. If you are not using third-party software to manage the job flow, this value is empty.</p>
    pub fn set_supported_products(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.supported_products = input;
        self
    }
    /// <p>A list of strings set by third-party software when the job flow is launched. If you are not using third-party software to manage the job flow, this value is empty.</p>
    pub fn get_supported_products(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.supported_products
    }
    /// <p>Indicates whether the cluster is visible to IAM principals in the Amazon Web Services account associated with the cluster. When <code>true</code>, IAM principals in the Amazon Web Services account can perform Amazon EMR cluster actions that their IAM policies allow. When <code>false</code>, only the IAM principal that created the cluster and the Amazon Web Services account root user can perform Amazon EMR actions, regardless of IAM permissions policies attached to other IAM principals.</p>
    /// <p>The default value is <code>true</code> if a value is not provided when creating a cluster using the Amazon EMR API <code>RunJobFlow</code> command, the CLI <a href="https://docs.aws.amazon.com/cli/latest/reference/emr/create-cluster.html">create-cluster</a> command, or the Amazon Web Services Management Console.</p>
    pub fn visible_to_all_users(mut self, input: bool) -> Self {
        self.visible_to_all_users = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether the cluster is visible to IAM principals in the Amazon Web Services account associated with the cluster. When <code>true</code>, IAM principals in the Amazon Web Services account can perform Amazon EMR cluster actions that their IAM policies allow. When <code>false</code>, only the IAM principal that created the cluster and the Amazon Web Services account root user can perform Amazon EMR actions, regardless of IAM permissions policies attached to other IAM principals.</p>
    /// <p>The default value is <code>true</code> if a value is not provided when creating a cluster using the Amazon EMR API <code>RunJobFlow</code> command, the CLI <a href="https://docs.aws.amazon.com/cli/latest/reference/emr/create-cluster.html">create-cluster</a> command, or the Amazon Web Services Management Console.</p>
    pub fn set_visible_to_all_users(mut self, input: ::std::option::Option<bool>) -> Self {
        self.visible_to_all_users = input;
        self
    }
    /// <p>Indicates whether the cluster is visible to IAM principals in the Amazon Web Services account associated with the cluster. When <code>true</code>, IAM principals in the Amazon Web Services account can perform Amazon EMR cluster actions that their IAM policies allow. When <code>false</code>, only the IAM principal that created the cluster and the Amazon Web Services account root user can perform Amazon EMR actions, regardless of IAM permissions policies attached to other IAM principals.</p>
    /// <p>The default value is <code>true</code> if a value is not provided when creating a cluster using the Amazon EMR API <code>RunJobFlow</code> command, the CLI <a href="https://docs.aws.amazon.com/cli/latest/reference/emr/create-cluster.html">create-cluster</a> command, or the Amazon Web Services Management Console.</p>
    pub fn get_visible_to_all_users(&self) -> &::std::option::Option<bool> {
        &self.visible_to_all_users
    }
    /// <p>The IAM role that was specified when the job flow was launched. The Amazon EC2 instances of the job flow assume this role.</p>
    pub fn job_flow_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.job_flow_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role that was specified when the job flow was launched. The Amazon EC2 instances of the job flow assume this role.</p>
    pub fn set_job_flow_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.job_flow_role = input;
        self
    }
    /// <p>The IAM role that was specified when the job flow was launched. The Amazon EC2 instances of the job flow assume this role.</p>
    pub fn get_job_flow_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.job_flow_role
    }
    /// <p>The IAM role that is assumed by the Amazon EMR service to access Amazon Web Services resources on your behalf.</p>
    pub fn service_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.service_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IAM role that is assumed by the Amazon EMR service to access Amazon Web Services resources on your behalf.</p>
    pub fn set_service_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.service_role = input;
        self
    }
    /// <p>The IAM role that is assumed by the Amazon EMR service to access Amazon Web Services resources on your behalf.</p>
    pub fn get_service_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.service_role
    }
    /// <p>An IAM role for automatic scaling policies. The default role is <code>EMR_AutoScaling_DefaultRole</code>. The IAM role provides a way for the automatic scaling feature to get the required permissions it needs to launch and terminate Amazon EC2 instances in an instance group.</p>
    pub fn auto_scaling_role(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auto_scaling_role = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An IAM role for automatic scaling policies. The default role is <code>EMR_AutoScaling_DefaultRole</code>. The IAM role provides a way for the automatic scaling feature to get the required permissions it needs to launch and terminate Amazon EC2 instances in an instance group.</p>
    pub fn set_auto_scaling_role(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auto_scaling_role = input;
        self
    }
    /// <p>An IAM role for automatic scaling policies. The default role is <code>EMR_AutoScaling_DefaultRole</code>. The IAM role provides a way for the automatic scaling feature to get the required permissions it needs to launch and terminate Amazon EC2 instances in an instance group.</p>
    pub fn get_auto_scaling_role(&self) -> &::std::option::Option<::std::string::String> {
        &self.auto_scaling_role
    }
    /// <p>The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized. <code>TERMINATE_AT_INSTANCE_HOUR</code> indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. <code>TERMINATE_AT_TASK_COMPLETION</code> indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. <code>TERMINATE_AT_TASK_COMPLETION</code> available only in Amazon EMR releases 4.1.0 and later, and is the default for releases of Amazon EMR earlier than 5.1.0.</p>
    pub fn scale_down_behavior(mut self, input: crate::types::ScaleDownBehavior) -> Self {
        self.scale_down_behavior = ::std::option::Option::Some(input);
        self
    }
    /// <p>The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized. <code>TERMINATE_AT_INSTANCE_HOUR</code> indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. <code>TERMINATE_AT_TASK_COMPLETION</code> indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. <code>TERMINATE_AT_TASK_COMPLETION</code> available only in Amazon EMR releases 4.1.0 and later, and is the default for releases of Amazon EMR earlier than 5.1.0.</p>
    pub fn set_scale_down_behavior(mut self, input: ::std::option::Option<crate::types::ScaleDownBehavior>) -> Self {
        self.scale_down_behavior = input;
        self
    }
    /// <p>The way that individual Amazon EC2 instances terminate when an automatic scale-in activity occurs or an instance group is resized. <code>TERMINATE_AT_INSTANCE_HOUR</code> indicates that Amazon EMR terminates nodes at the instance-hour boundary, regardless of when the request to terminate the instance was submitted. This option is only available with Amazon EMR 5.1.0 and later and is the default for clusters created using that version. <code>TERMINATE_AT_TASK_COMPLETION</code> indicates that Amazon EMR adds nodes to a deny list and drains tasks from nodes before terminating the Amazon EC2 instances, regardless of the instance-hour boundary. With either behavior, Amazon EMR removes the least active nodes first and blocks instance termination if it could lead to HDFS corruption. <code>TERMINATE_AT_TASK_COMPLETION</code> available only in Amazon EMR releases 4.1.0 and later, and is the default for releases of Amazon EMR earlier than 5.1.0.</p>
    pub fn get_scale_down_behavior(&self) -> &::std::option::Option<crate::types::ScaleDownBehavior> {
        &self.scale_down_behavior
    }
    /// Consumes the builder and constructs a [`JobFlowDetail`](crate::types::JobFlowDetail).
    pub fn build(self) -> crate::types::JobFlowDetail {
        crate::types::JobFlowDetail {
            job_flow_id: self.job_flow_id,
            name: self.name,
            log_uri: self.log_uri,
            log_encryption_kms_key_id: self.log_encryption_kms_key_id,
            ami_version: self.ami_version,
            execution_status_detail: self.execution_status_detail,
            instances: self.instances,
            steps: self.steps,
            bootstrap_actions: self.bootstrap_actions,
            supported_products: self.supported_products,
            visible_to_all_users: self.visible_to_all_users,
            job_flow_role: self.job_flow_role,
            service_role: self.service_role,
            auto_scaling_role: self.auto_scaling_role,
            scale_down_behavior: self.scale_down_behavior,
        }
    }
}
