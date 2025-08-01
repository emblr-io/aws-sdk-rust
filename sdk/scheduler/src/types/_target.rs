// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The schedule's target. EventBridge Scheduler supports templated target that invoke common API operations, as well as universal targets that you can customize to invoke over 6,000 API operations across more than 270 services. You can only specify one templated or universal target for a schedule.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Target {
    /// <p>The Amazon Resource Name (ARN) of the target.</p>
    pub arn: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the IAM role that EventBridge Scheduler will use for this target when the schedule is invoked.</p>
    pub role_arn: ::std::string::String,
    /// <p>An object that contains information about an Amazon SQS queue that EventBridge Scheduler uses as a dead-letter queue for your schedule. If specified, EventBridge Scheduler delivers failed events that could not be successfully delivered to a target to the queue.</p>
    pub dead_letter_config: ::std::option::Option<crate::types::DeadLetterConfig>,
    /// <p>A <code>RetryPolicy</code> object that includes information about the retry policy settings, including the maximum age of an event, and the maximum number of times EventBridge Scheduler will try to deliver the event to a target.</p>
    pub retry_policy: ::std::option::Option<crate::types::RetryPolicy>,
    /// <p>The text, or well-formed JSON, passed to the target. If you are configuring a templated Lambda, AWS Step Functions, or Amazon EventBridge target, the input must be a well-formed JSON. For all other target types, a JSON is not required. If you do not specify anything for this field, EventBridge Scheduler delivers a default notification to the target.</p>
    pub input: ::std::option::Option<::std::string::String>,
    /// <p>The templated target type for the Amazon ECS <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html"> <code>RunTask</code> </a> API operation.</p>
    pub ecs_parameters: ::std::option::Option<crate::types::EcsParameters>,
    /// <p>The templated target type for the EventBridge <a href="https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html"> <code>PutEvents</code> </a> API operation.</p>
    pub event_bridge_parameters: ::std::option::Option<crate::types::EventBridgeParameters>,
    /// <p>The templated target type for the Amazon Kinesis <a href="kinesis/latest/APIReference/API_PutRecord.html"> <code>PutRecord</code> </a> API operation.</p>
    pub kinesis_parameters: ::std::option::Option<crate::types::KinesisParameters>,
    /// <p>The templated target type for the Amazon SageMaker <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_StartPipelineExecution.html"> <code>StartPipelineExecution</code> </a> API operation.</p>
    pub sage_maker_pipeline_parameters: ::std::option::Option<crate::types::SageMakerPipelineParameters>,
    /// <p>The templated target type for the Amazon SQS <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html"> <code>SendMessage</code> </a> API operation. Contains the message group ID to use when the target is a FIFO queue. If you specify an Amazon SQS FIFO queue as a target, the queue must have content-based deduplication enabled. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-messagededuplicationid-property.html">Using the Amazon SQS message deduplication ID</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub sqs_parameters: ::std::option::Option<crate::types::SqsParameters>,
}
impl Target {
    /// <p>The Amazon Resource Name (ARN) of the target.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that EventBridge Scheduler will use for this target when the schedule is invoked.</p>
    pub fn role_arn(&self) -> &str {
        use std::ops::Deref;
        self.role_arn.deref()
    }
    /// <p>An object that contains information about an Amazon SQS queue that EventBridge Scheduler uses as a dead-letter queue for your schedule. If specified, EventBridge Scheduler delivers failed events that could not be successfully delivered to a target to the queue.</p>
    pub fn dead_letter_config(&self) -> ::std::option::Option<&crate::types::DeadLetterConfig> {
        self.dead_letter_config.as_ref()
    }
    /// <p>A <code>RetryPolicy</code> object that includes information about the retry policy settings, including the maximum age of an event, and the maximum number of times EventBridge Scheduler will try to deliver the event to a target.</p>
    pub fn retry_policy(&self) -> ::std::option::Option<&crate::types::RetryPolicy> {
        self.retry_policy.as_ref()
    }
    /// <p>The text, or well-formed JSON, passed to the target. If you are configuring a templated Lambda, AWS Step Functions, or Amazon EventBridge target, the input must be a well-formed JSON. For all other target types, a JSON is not required. If you do not specify anything for this field, EventBridge Scheduler delivers a default notification to the target.</p>
    pub fn input(&self) -> ::std::option::Option<&str> {
        self.input.as_deref()
    }
    /// <p>The templated target type for the Amazon ECS <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html"> <code>RunTask</code> </a> API operation.</p>
    pub fn ecs_parameters(&self) -> ::std::option::Option<&crate::types::EcsParameters> {
        self.ecs_parameters.as_ref()
    }
    /// <p>The templated target type for the EventBridge <a href="https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html"> <code>PutEvents</code> </a> API operation.</p>
    pub fn event_bridge_parameters(&self) -> ::std::option::Option<&crate::types::EventBridgeParameters> {
        self.event_bridge_parameters.as_ref()
    }
    /// <p>The templated target type for the Amazon Kinesis <a href="kinesis/latest/APIReference/API_PutRecord.html"> <code>PutRecord</code> </a> API operation.</p>
    pub fn kinesis_parameters(&self) -> ::std::option::Option<&crate::types::KinesisParameters> {
        self.kinesis_parameters.as_ref()
    }
    /// <p>The templated target type for the Amazon SageMaker <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_StartPipelineExecution.html"> <code>StartPipelineExecution</code> </a> API operation.</p>
    pub fn sage_maker_pipeline_parameters(&self) -> ::std::option::Option<&crate::types::SageMakerPipelineParameters> {
        self.sage_maker_pipeline_parameters.as_ref()
    }
    /// <p>The templated target type for the Amazon SQS <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html"> <code>SendMessage</code> </a> API operation. Contains the message group ID to use when the target is a FIFO queue. If you specify an Amazon SQS FIFO queue as a target, the queue must have content-based deduplication enabled. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-messagededuplicationid-property.html">Using the Amazon SQS message deduplication ID</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn sqs_parameters(&self) -> ::std::option::Option<&crate::types::SqsParameters> {
        self.sqs_parameters.as_ref()
    }
}
impl Target {
    /// Creates a new builder-style object to manufacture [`Target`](crate::types::Target).
    pub fn builder() -> crate::types::builders::TargetBuilder {
        crate::types::builders::TargetBuilder::default()
    }
}

/// A builder for [`Target`](crate::types::Target).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TargetBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) dead_letter_config: ::std::option::Option<crate::types::DeadLetterConfig>,
    pub(crate) retry_policy: ::std::option::Option<crate::types::RetryPolicy>,
    pub(crate) input: ::std::option::Option<::std::string::String>,
    pub(crate) ecs_parameters: ::std::option::Option<crate::types::EcsParameters>,
    pub(crate) event_bridge_parameters: ::std::option::Option<crate::types::EventBridgeParameters>,
    pub(crate) kinesis_parameters: ::std::option::Option<crate::types::KinesisParameters>,
    pub(crate) sage_maker_pipeline_parameters: ::std::option::Option<crate::types::SageMakerPipelineParameters>,
    pub(crate) sqs_parameters: ::std::option::Option<crate::types::SqsParameters>,
}
impl TargetBuilder {
    /// <p>The Amazon Resource Name (ARN) of the target.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the target.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that EventBridge Scheduler will use for this target when the schedule is invoked.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that EventBridge Scheduler will use for this target when the schedule is invoked.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role that EventBridge Scheduler will use for this target when the schedule is invoked.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>An object that contains information about an Amazon SQS queue that EventBridge Scheduler uses as a dead-letter queue for your schedule. If specified, EventBridge Scheduler delivers failed events that could not be successfully delivered to a target to the queue.</p>
    pub fn dead_letter_config(mut self, input: crate::types::DeadLetterConfig) -> Self {
        self.dead_letter_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains information about an Amazon SQS queue that EventBridge Scheduler uses as a dead-letter queue for your schedule. If specified, EventBridge Scheduler delivers failed events that could not be successfully delivered to a target to the queue.</p>
    pub fn set_dead_letter_config(mut self, input: ::std::option::Option<crate::types::DeadLetterConfig>) -> Self {
        self.dead_letter_config = input;
        self
    }
    /// <p>An object that contains information about an Amazon SQS queue that EventBridge Scheduler uses as a dead-letter queue for your schedule. If specified, EventBridge Scheduler delivers failed events that could not be successfully delivered to a target to the queue.</p>
    pub fn get_dead_letter_config(&self) -> &::std::option::Option<crate::types::DeadLetterConfig> {
        &self.dead_letter_config
    }
    /// <p>A <code>RetryPolicy</code> object that includes information about the retry policy settings, including the maximum age of an event, and the maximum number of times EventBridge Scheduler will try to deliver the event to a target.</p>
    pub fn retry_policy(mut self, input: crate::types::RetryPolicy) -> Self {
        self.retry_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>RetryPolicy</code> object that includes information about the retry policy settings, including the maximum age of an event, and the maximum number of times EventBridge Scheduler will try to deliver the event to a target.</p>
    pub fn set_retry_policy(mut self, input: ::std::option::Option<crate::types::RetryPolicy>) -> Self {
        self.retry_policy = input;
        self
    }
    /// <p>A <code>RetryPolicy</code> object that includes information about the retry policy settings, including the maximum age of an event, and the maximum number of times EventBridge Scheduler will try to deliver the event to a target.</p>
    pub fn get_retry_policy(&self) -> &::std::option::Option<crate::types::RetryPolicy> {
        &self.retry_policy
    }
    /// <p>The text, or well-formed JSON, passed to the target. If you are configuring a templated Lambda, AWS Step Functions, or Amazon EventBridge target, the input must be a well-formed JSON. For all other target types, a JSON is not required. If you do not specify anything for this field, EventBridge Scheduler delivers a default notification to the target.</p>
    pub fn input(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The text, or well-formed JSON, passed to the target. If you are configuring a templated Lambda, AWS Step Functions, or Amazon EventBridge target, the input must be a well-formed JSON. For all other target types, a JSON is not required. If you do not specify anything for this field, EventBridge Scheduler delivers a default notification to the target.</p>
    pub fn set_input(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input = input;
        self
    }
    /// <p>The text, or well-formed JSON, passed to the target. If you are configuring a templated Lambda, AWS Step Functions, or Amazon EventBridge target, the input must be a well-formed JSON. For all other target types, a JSON is not required. If you do not specify anything for this field, EventBridge Scheduler delivers a default notification to the target.</p>
    pub fn get_input(&self) -> &::std::option::Option<::std::string::String> {
        &self.input
    }
    /// <p>The templated target type for the Amazon ECS <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html"> <code>RunTask</code> </a> API operation.</p>
    pub fn ecs_parameters(mut self, input: crate::types::EcsParameters) -> Self {
        self.ecs_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The templated target type for the Amazon ECS <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html"> <code>RunTask</code> </a> API operation.</p>
    pub fn set_ecs_parameters(mut self, input: ::std::option::Option<crate::types::EcsParameters>) -> Self {
        self.ecs_parameters = input;
        self
    }
    /// <p>The templated target type for the Amazon ECS <a href="https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RunTask.html"> <code>RunTask</code> </a> API operation.</p>
    pub fn get_ecs_parameters(&self) -> &::std::option::Option<crate::types::EcsParameters> {
        &self.ecs_parameters
    }
    /// <p>The templated target type for the EventBridge <a href="https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html"> <code>PutEvents</code> </a> API operation.</p>
    pub fn event_bridge_parameters(mut self, input: crate::types::EventBridgeParameters) -> Self {
        self.event_bridge_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The templated target type for the EventBridge <a href="https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html"> <code>PutEvents</code> </a> API operation.</p>
    pub fn set_event_bridge_parameters(mut self, input: ::std::option::Option<crate::types::EventBridgeParameters>) -> Self {
        self.event_bridge_parameters = input;
        self
    }
    /// <p>The templated target type for the EventBridge <a href="https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_PutEvents.html"> <code>PutEvents</code> </a> API operation.</p>
    pub fn get_event_bridge_parameters(&self) -> &::std::option::Option<crate::types::EventBridgeParameters> {
        &self.event_bridge_parameters
    }
    /// <p>The templated target type for the Amazon Kinesis <a href="kinesis/latest/APIReference/API_PutRecord.html"> <code>PutRecord</code> </a> API operation.</p>
    pub fn kinesis_parameters(mut self, input: crate::types::KinesisParameters) -> Self {
        self.kinesis_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The templated target type for the Amazon Kinesis <a href="kinesis/latest/APIReference/API_PutRecord.html"> <code>PutRecord</code> </a> API operation.</p>
    pub fn set_kinesis_parameters(mut self, input: ::std::option::Option<crate::types::KinesisParameters>) -> Self {
        self.kinesis_parameters = input;
        self
    }
    /// <p>The templated target type for the Amazon Kinesis <a href="kinesis/latest/APIReference/API_PutRecord.html"> <code>PutRecord</code> </a> API operation.</p>
    pub fn get_kinesis_parameters(&self) -> &::std::option::Option<crate::types::KinesisParameters> {
        &self.kinesis_parameters
    }
    /// <p>The templated target type for the Amazon SageMaker <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_StartPipelineExecution.html"> <code>StartPipelineExecution</code> </a> API operation.</p>
    pub fn sage_maker_pipeline_parameters(mut self, input: crate::types::SageMakerPipelineParameters) -> Self {
        self.sage_maker_pipeline_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The templated target type for the Amazon SageMaker <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_StartPipelineExecution.html"> <code>StartPipelineExecution</code> </a> API operation.</p>
    pub fn set_sage_maker_pipeline_parameters(mut self, input: ::std::option::Option<crate::types::SageMakerPipelineParameters>) -> Self {
        self.sage_maker_pipeline_parameters = input;
        self
    }
    /// <p>The templated target type for the Amazon SageMaker <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_StartPipelineExecution.html"> <code>StartPipelineExecution</code> </a> API operation.</p>
    pub fn get_sage_maker_pipeline_parameters(&self) -> &::std::option::Option<crate::types::SageMakerPipelineParameters> {
        &self.sage_maker_pipeline_parameters
    }
    /// <p>The templated target type for the Amazon SQS <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html"> <code>SendMessage</code> </a> API operation. Contains the message group ID to use when the target is a FIFO queue. If you specify an Amazon SQS FIFO queue as a target, the queue must have content-based deduplication enabled. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-messagededuplicationid-property.html">Using the Amazon SQS message deduplication ID</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn sqs_parameters(mut self, input: crate::types::SqsParameters) -> Self {
        self.sqs_parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>The templated target type for the Amazon SQS <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html"> <code>SendMessage</code> </a> API operation. Contains the message group ID to use when the target is a FIFO queue. If you specify an Amazon SQS FIFO queue as a target, the queue must have content-based deduplication enabled. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-messagededuplicationid-property.html">Using the Amazon SQS message deduplication ID</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn set_sqs_parameters(mut self, input: ::std::option::Option<crate::types::SqsParameters>) -> Self {
        self.sqs_parameters = input;
        self
    }
    /// <p>The templated target type for the Amazon SQS <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/APIReference/API_SendMessage.html"> <code>SendMessage</code> </a> API operation. Contains the message group ID to use when the target is a FIFO queue. If you specify an Amazon SQS FIFO queue as a target, the queue must have content-based deduplication enabled. For more information, see <a href="https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/using-messagededuplicationid-property.html">Using the Amazon SQS message deduplication ID</a> in the <i>Amazon SQS Developer Guide</i>.</p>
    pub fn get_sqs_parameters(&self) -> &::std::option::Option<crate::types::SqsParameters> {
        &self.sqs_parameters
    }
    /// Consumes the builder and constructs a [`Target`](crate::types::Target).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::types::builders::TargetBuilder::arn)
    /// - [`role_arn`](crate::types::builders::TargetBuilder::role_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::Target, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Target {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building Target",
                )
            })?,
            role_arn: self.role_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "role_arn",
                    "role_arn was not specified but it is required when building Target",
                )
            })?,
            dead_letter_config: self.dead_letter_config,
            retry_policy: self.retry_policy,
            input: self.input,
            ecs_parameters: self.ecs_parameters,
            event_bridge_parameters: self.event_bridge_parameters,
            kinesis_parameters: self.kinesis_parameters,
            sage_maker_pipeline_parameters: self.sage_maker_pipeline_parameters,
            sqs_parameters: self.sqs_parameters,
        })
    }
}
