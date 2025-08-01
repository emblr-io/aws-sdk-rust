// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCloudFormationChangeSetInput {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub application_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of values that you must specify before you can deploy certain applications. Some applications might include resources that can affect permissions in your AWS account, for example, by creating new AWS Identity and Access Management (IAM) users. For those applications, you must explicitly acknowledge their capabilities by specifying this parameter.</p>
    /// <p>The only valid values are CAPABILITY_IAM, CAPABILITY_NAMED_IAM, CAPABILITY_RESOURCE_POLICY, and CAPABILITY_AUTO_EXPAND.</p>
    /// <p>The following resources require you to specify CAPABILITY_IAM or CAPABILITY_NAMED_IAM: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html">AWS::IAM::Group</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html">AWS::IAM::InstanceProfile</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM::Policy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html">AWS::IAM::Role</a>. If the application contains IAM resources, you can specify either CAPABILITY_IAM or CAPABILITY_NAMED_IAM. If the application contains IAM resources with custom names, you must specify CAPABILITY_NAMED_IAM.</p>
    /// <p>The following resources require you to specify CAPABILITY_RESOURCE_POLICY: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html">AWS::Lambda::Permission</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM:Policy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalingpolicy.html">AWS::ApplicationAutoScaling::ScalingPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html">AWS::S3::BucketPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-policy.html">AWS::SQS::QueuePolicy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html">AWS::SNS:TopicPolicy</a>.</p>
    /// <p>Applications that contain one or more nested applications require you to specify CAPABILITY_AUTO_EXPAND.</p>
    /// <p>If your application template contains any of the above resources, we recommend that you review all permissions associated with the application before deploying. If you don't specify this parameter for an application that requires capabilities, the call will fail.</p>
    pub capabilities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub change_set_name: ::std::option::Option<::std::string::String>,
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub notification_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A list of parameter values for the parameters of the application.</p>
    pub parameter_overrides: ::std::option::Option<::std::vec::Vec<crate::types::ParameterValue>>,
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub resource_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub rollback_configuration: ::std::option::Option<crate::types::RollbackConfiguration>,
    /// <p>The semantic version of the application:</p>
    /// <p><a href="https://semver.org/">https://semver.org/</a></p>
    pub semantic_version: ::std::option::Option<::std::string::String>,
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub stack_name: ::std::option::Option<::std::string::String>,
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>The UUID returned by CreateCloudFormationTemplate.</p>
    /// <p>Pattern: \[0-9a-fA-F\]{8}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{12}</p>
    pub template_id: ::std::option::Option<::std::string::String>,
}
impl CreateCloudFormationChangeSetInput {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn application_id(&self) -> ::std::option::Option<&str> {
        self.application_id.as_deref()
    }
    /// <p>A list of values that you must specify before you can deploy certain applications. Some applications might include resources that can affect permissions in your AWS account, for example, by creating new AWS Identity and Access Management (IAM) users. For those applications, you must explicitly acknowledge their capabilities by specifying this parameter.</p>
    /// <p>The only valid values are CAPABILITY_IAM, CAPABILITY_NAMED_IAM, CAPABILITY_RESOURCE_POLICY, and CAPABILITY_AUTO_EXPAND.</p>
    /// <p>The following resources require you to specify CAPABILITY_IAM or CAPABILITY_NAMED_IAM: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html">AWS::IAM::Group</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html">AWS::IAM::InstanceProfile</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM::Policy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html">AWS::IAM::Role</a>. If the application contains IAM resources, you can specify either CAPABILITY_IAM or CAPABILITY_NAMED_IAM. If the application contains IAM resources with custom names, you must specify CAPABILITY_NAMED_IAM.</p>
    /// <p>The following resources require you to specify CAPABILITY_RESOURCE_POLICY: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html">AWS::Lambda::Permission</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM:Policy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalingpolicy.html">AWS::ApplicationAutoScaling::ScalingPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html">AWS::S3::BucketPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-policy.html">AWS::SQS::QueuePolicy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html">AWS::SNS:TopicPolicy</a>.</p>
    /// <p>Applications that contain one or more nested applications require you to specify CAPABILITY_AUTO_EXPAND.</p>
    /// <p>If your application template contains any of the above resources, we recommend that you review all permissions associated with the application before deploying. If you don't specify this parameter for an application that requires capabilities, the call will fail.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.capabilities.is_none()`.
    pub fn capabilities(&self) -> &[::std::string::String] {
        self.capabilities.as_deref().unwrap_or_default()
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn change_set_name(&self) -> ::std::option::Option<&str> {
        self.change_set_name.as_deref()
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.notification_arns.is_none()`.
    pub fn notification_arns(&self) -> &[::std::string::String] {
        self.notification_arns.as_deref().unwrap_or_default()
    }
    /// <p>A list of parameter values for the parameters of the application.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.parameter_overrides.is_none()`.
    pub fn parameter_overrides(&self) -> &[crate::types::ParameterValue] {
        self.parameter_overrides.as_deref().unwrap_or_default()
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.resource_types.is_none()`.
    pub fn resource_types(&self) -> &[::std::string::String] {
        self.resource_types.as_deref().unwrap_or_default()
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn rollback_configuration(&self) -> ::std::option::Option<&crate::types::RollbackConfiguration> {
        self.rollback_configuration.as_ref()
    }
    /// <p>The semantic version of the application:</p>
    /// <p><a href="https://semver.org/">https://semver.org/</a></p>
    pub fn semantic_version(&self) -> ::std::option::Option<&str> {
        self.semantic_version.as_deref()
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn stack_name(&self) -> ::std::option::Option<&str> {
        self.stack_name.as_deref()
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>The UUID returned by CreateCloudFormationTemplate.</p>
    /// <p>Pattern: \[0-9a-fA-F\]{8}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{12}</p>
    pub fn template_id(&self) -> ::std::option::Option<&str> {
        self.template_id.as_deref()
    }
}
impl CreateCloudFormationChangeSetInput {
    /// Creates a new builder-style object to manufacture [`CreateCloudFormationChangeSetInput`](crate::operation::create_cloud_formation_change_set::CreateCloudFormationChangeSetInput).
    pub fn builder() -> crate::operation::create_cloud_formation_change_set::builders::CreateCloudFormationChangeSetInputBuilder {
        crate::operation::create_cloud_formation_change_set::builders::CreateCloudFormationChangeSetInputBuilder::default()
    }
}

/// A builder for [`CreateCloudFormationChangeSetInput`](crate::operation::create_cloud_formation_change_set::CreateCloudFormationChangeSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCloudFormationChangeSetInputBuilder {
    pub(crate) application_id: ::std::option::Option<::std::string::String>,
    pub(crate) capabilities: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) change_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) notification_arns: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) parameter_overrides: ::std::option::Option<::std::vec::Vec<crate::types::ParameterValue>>,
    pub(crate) resource_types: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) rollback_configuration: ::std::option::Option<crate::types::RollbackConfiguration>,
    pub(crate) semantic_version: ::std::option::Option<::std::string::String>,
    pub(crate) stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) template_id: ::std::option::Option<::std::string::String>,
}
impl CreateCloudFormationChangeSetInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    /// This field is required.
    pub fn application_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn set_application_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_id = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn get_application_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_id
    }
    /// Appends an item to `capabilities`.
    ///
    /// To override the contents of this collection use [`set_capabilities`](Self::set_capabilities).
    ///
    /// <p>A list of values that you must specify before you can deploy certain applications. Some applications might include resources that can affect permissions in your AWS account, for example, by creating new AWS Identity and Access Management (IAM) users. For those applications, you must explicitly acknowledge their capabilities by specifying this parameter.</p>
    /// <p>The only valid values are CAPABILITY_IAM, CAPABILITY_NAMED_IAM, CAPABILITY_RESOURCE_POLICY, and CAPABILITY_AUTO_EXPAND.</p>
    /// <p>The following resources require you to specify CAPABILITY_IAM or CAPABILITY_NAMED_IAM: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html">AWS::IAM::Group</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html">AWS::IAM::InstanceProfile</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM::Policy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html">AWS::IAM::Role</a>. If the application contains IAM resources, you can specify either CAPABILITY_IAM or CAPABILITY_NAMED_IAM. If the application contains IAM resources with custom names, you must specify CAPABILITY_NAMED_IAM.</p>
    /// <p>The following resources require you to specify CAPABILITY_RESOURCE_POLICY: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html">AWS::Lambda::Permission</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM:Policy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalingpolicy.html">AWS::ApplicationAutoScaling::ScalingPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html">AWS::S3::BucketPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-policy.html">AWS::SQS::QueuePolicy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html">AWS::SNS:TopicPolicy</a>.</p>
    /// <p>Applications that contain one or more nested applications require you to specify CAPABILITY_AUTO_EXPAND.</p>
    /// <p>If your application template contains any of the above resources, we recommend that you review all permissions associated with the application before deploying. If you don't specify this parameter for an application that requires capabilities, the call will fail.</p>
    pub fn capabilities(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.capabilities.unwrap_or_default();
        v.push(input.into());
        self.capabilities = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of values that you must specify before you can deploy certain applications. Some applications might include resources that can affect permissions in your AWS account, for example, by creating new AWS Identity and Access Management (IAM) users. For those applications, you must explicitly acknowledge their capabilities by specifying this parameter.</p>
    /// <p>The only valid values are CAPABILITY_IAM, CAPABILITY_NAMED_IAM, CAPABILITY_RESOURCE_POLICY, and CAPABILITY_AUTO_EXPAND.</p>
    /// <p>The following resources require you to specify CAPABILITY_IAM or CAPABILITY_NAMED_IAM: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html">AWS::IAM::Group</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html">AWS::IAM::InstanceProfile</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM::Policy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html">AWS::IAM::Role</a>. If the application contains IAM resources, you can specify either CAPABILITY_IAM or CAPABILITY_NAMED_IAM. If the application contains IAM resources with custom names, you must specify CAPABILITY_NAMED_IAM.</p>
    /// <p>The following resources require you to specify CAPABILITY_RESOURCE_POLICY: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html">AWS::Lambda::Permission</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM:Policy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalingpolicy.html">AWS::ApplicationAutoScaling::ScalingPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html">AWS::S3::BucketPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-policy.html">AWS::SQS::QueuePolicy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html">AWS::SNS:TopicPolicy</a>.</p>
    /// <p>Applications that contain one or more nested applications require you to specify CAPABILITY_AUTO_EXPAND.</p>
    /// <p>If your application template contains any of the above resources, we recommend that you review all permissions associated with the application before deploying. If you don't specify this parameter for an application that requires capabilities, the call will fail.</p>
    pub fn set_capabilities(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.capabilities = input;
        self
    }
    /// <p>A list of values that you must specify before you can deploy certain applications. Some applications might include resources that can affect permissions in your AWS account, for example, by creating new AWS Identity and Access Management (IAM) users. For those applications, you must explicitly acknowledge their capabilities by specifying this parameter.</p>
    /// <p>The only valid values are CAPABILITY_IAM, CAPABILITY_NAMED_IAM, CAPABILITY_RESOURCE_POLICY, and CAPABILITY_AUTO_EXPAND.</p>
    /// <p>The following resources require you to specify CAPABILITY_IAM or CAPABILITY_NAMED_IAM: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-iam-group.html">AWS::IAM::Group</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-instanceprofile.html">AWS::IAM::InstanceProfile</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM::Policy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-role.html">AWS::IAM::Role</a>. If the application contains IAM resources, you can specify either CAPABILITY_IAM or CAPABILITY_NAMED_IAM. If the application contains IAM resources with custom names, you must specify CAPABILITY_NAMED_IAM.</p>
    /// <p>The following resources require you to specify CAPABILITY_RESOURCE_POLICY: <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-lambda-permission.html">AWS::Lambda::Permission</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-iam-policy.html">AWS::IAM:Policy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-applicationautoscaling-scalingpolicy.html">AWS::ApplicationAutoScaling::ScalingPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-s3-policy.html">AWS::S3::BucketPolicy</a>, <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sqs-policy.html">AWS::SQS::QueuePolicy</a>, and <a href="https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-sns-policy.html">AWS::SNS:TopicPolicy</a>.</p>
    /// <p>Applications that contain one or more nested applications require you to specify CAPABILITY_AUTO_EXPAND.</p>
    /// <p>If your application template contains any of the above resources, we recommend that you review all permissions associated with the application before deploying. If you don't specify this parameter for an application that requires capabilities, the call will fail.</p>
    pub fn get_capabilities(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.capabilities
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn change_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn set_change_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_set_name = input;
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn get_change_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_set_name
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `notification_arns`.
    ///
    /// To override the contents of this collection use [`set_notification_arns`](Self::set_notification_arns).
    ///
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn notification_arns(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.notification_arns.unwrap_or_default();
        v.push(input.into());
        self.notification_arns = ::std::option::Option::Some(v);
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn set_notification_arns(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.notification_arns = input;
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn get_notification_arns(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.notification_arns
    }
    /// Appends an item to `parameter_overrides`.
    ///
    /// To override the contents of this collection use [`set_parameter_overrides`](Self::set_parameter_overrides).
    ///
    /// <p>A list of parameter values for the parameters of the application.</p>
    pub fn parameter_overrides(mut self, input: crate::types::ParameterValue) -> Self {
        let mut v = self.parameter_overrides.unwrap_or_default();
        v.push(input);
        self.parameter_overrides = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of parameter values for the parameters of the application.</p>
    pub fn set_parameter_overrides(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ParameterValue>>) -> Self {
        self.parameter_overrides = input;
        self
    }
    /// <p>A list of parameter values for the parameters of the application.</p>
    pub fn get_parameter_overrides(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ParameterValue>> {
        &self.parameter_overrides
    }
    /// Appends an item to `resource_types`.
    ///
    /// To override the contents of this collection use [`set_resource_types`](Self::set_resource_types).
    ///
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn resource_types(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.resource_types.unwrap_or_default();
        v.push(input.into());
        self.resource_types = ::std::option::Option::Some(v);
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn set_resource_types(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.resource_types = input;
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn get_resource_types(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.resource_types
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn rollback_configuration(mut self, input: crate::types::RollbackConfiguration) -> Self {
        self.rollback_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn set_rollback_configuration(mut self, input: ::std::option::Option<crate::types::RollbackConfiguration>) -> Self {
        self.rollback_configuration = input;
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn get_rollback_configuration(&self) -> &::std::option::Option<crate::types::RollbackConfiguration> {
        &self.rollback_configuration
    }
    /// <p>The semantic version of the application:</p>
    /// <p><a href="https://semver.org/">https://semver.org/</a></p>
    pub fn semantic_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.semantic_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The semantic version of the application:</p>
    /// <p><a href="https://semver.org/">https://semver.org/</a></p>
    pub fn set_semantic_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.semantic_version = input;
        self
    }
    /// <p>The semantic version of the application:</p>
    /// <p><a href="https://semver.org/">https://semver.org/</a></p>
    pub fn get_semantic_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.semantic_version
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    /// This field is required.
    pub fn stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn set_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stack_name = input;
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn get_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stack_name
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>This property corresponds to the parameter of the same name for the <i>AWS CloudFormation <a href="https://docs.aws.amazon.com/goto/WebAPI/cloudformation-2010-05-15/CreateChangeSet">CreateChangeSet</a> </i> API.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>The UUID returned by CreateCloudFormationTemplate.</p>
    /// <p>Pattern: \[0-9a-fA-F\]{8}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{12}</p>
    pub fn template_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The UUID returned by CreateCloudFormationTemplate.</p>
    /// <p>Pattern: \[0-9a-fA-F\]{8}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{12}</p>
    pub fn set_template_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_id = input;
        self
    }
    /// <p>The UUID returned by CreateCloudFormationTemplate.</p>
    /// <p>Pattern: \[0-9a-fA-F\]{8}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{4}\-\[0-9a-fA-F\]{12}</p>
    pub fn get_template_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_id
    }
    /// Consumes the builder and constructs a [`CreateCloudFormationChangeSetInput`](crate::operation::create_cloud_formation_change_set::CreateCloudFormationChangeSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_cloud_formation_change_set::CreateCloudFormationChangeSetInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_cloud_formation_change_set::CreateCloudFormationChangeSetInput {
            application_id: self.application_id,
            capabilities: self.capabilities,
            change_set_name: self.change_set_name,
            client_token: self.client_token,
            description: self.description,
            notification_arns: self.notification_arns,
            parameter_overrides: self.parameter_overrides,
            resource_types: self.resource_types,
            rollback_configuration: self.rollback_configuration,
            semantic_version: self.semantic_version,
            stack_name: self.stack_name,
            tags: self.tags,
            template_id: self.template_id,
        })
    }
}
