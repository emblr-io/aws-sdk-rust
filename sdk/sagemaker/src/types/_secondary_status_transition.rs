// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An array element of <code>SecondaryStatusTransitions</code> for <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeTrainingJob.html">DescribeTrainingJob</a>. It provides additional details about a status that the training job has transitioned through. A training job can be in one of several states, for example, starting, downloading, training, or uploading. Within each state, there are a number of intermediate states. For example, within the starting state, SageMaker could be starting the training job or launching the ML instances. These transitional states are referred to as the job's secondary status.</p>
/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SecondaryStatusTransition {
    /// <p>Contains a secondary status information from a training job.</p>
    /// <p>Status might be one of the following secondary statuses:</p>
    /// <dl>
    /// <dt>
    /// InProgress
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Starting</code> - Starting the training job.</p></li>
    /// <li>
    /// <p><code>Downloading</code> - An optional stage for algorithms that support <code>File</code> training input mode. It indicates that data is being downloaded to the ML storage volumes.</p></li>
    /// <li>
    /// <p><code>Training</code> - Training is in progress.</p></li>
    /// <li>
    /// <p><code>Uploading</code> - Training is complete and the model artifacts are being uploaded to the S3 location.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Completed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code> - The training job has completed.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Failed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The training job has failed. The reason for the failure is returned in the <code>FailureReason</code> field of <code>DescribeTrainingJobResponse</code>.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopped
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>MaxRuntimeExceeded</code> - The job stopped because it exceeded the maximum allowed runtime.</p></li>
    /// <li>
    /// <p><code>Stopped</code> - The training job has stopped.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopping
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Stopping</code> - Stopping the training job.</p></li>
    /// </ul>
    /// </dd>
    /// </dl>
    /// <p>We no longer support the following secondary statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>LaunchingMLInstances</code></p></li>
    /// <li>
    /// <p><code>PreparingTrainingStack</code></p></li>
    /// <li>
    /// <p><code>DownloadingTrainingImage</code></p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::SecondaryStatus>,
    /// <p>A timestamp that shows when the training job transitioned to the current secondary status state.</p>
    pub start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A timestamp that shows when the training job transitioned out of this secondary status state into another secondary status state or when the training job has ended.</p>
    pub end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A detailed description of the progress within a secondary status.</p>
    /// <p>SageMaker provides secondary statuses and status messages that apply to each of them:</p>
    /// <dl>
    /// <dt>
    /// Starting
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Starting the training job.</p></li>
    /// <li>
    /// <p>Launching requested ML instances.</p></li>
    /// <li>
    /// <p>Insufficient capacity error from EC2 while launching instances, retrying!</p></li>
    /// <li>
    /// <p>Launched instance was unhealthy, replacing it!</p></li>
    /// <li>
    /// <p>Preparing the instances for training.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Training
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Training image download completed. Training in progress.</p></li>
    /// </ul>
    /// </dd>
    /// </dl><important>
    /// <p>Status messages are subject to change. Therefore, we recommend not including them in code that programmatically initiates actions. For examples, don't use status messages in if statements.</p>
    /// </important>
    /// <p>To have an overview of your training job's progress, view <code>TrainingJobStatus</code> and <code>SecondaryStatus</code> in <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeTrainingJob.html">DescribeTrainingJob</a>, and <code>StatusMessage</code> together. For example, at the start of a training job, you might see the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>TrainingJobStatus</code> - InProgress</p></li>
    /// <li>
    /// <p><code>SecondaryStatus</code> - Training</p></li>
    /// <li>
    /// <p><code>StatusMessage</code> - Downloading the training image</p></li>
    /// </ul>
    pub status_message: ::std::option::Option<::std::string::String>,
}
impl SecondaryStatusTransition {
    /// <p>Contains a secondary status information from a training job.</p>
    /// <p>Status might be one of the following secondary statuses:</p>
    /// <dl>
    /// <dt>
    /// InProgress
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Starting</code> - Starting the training job.</p></li>
    /// <li>
    /// <p><code>Downloading</code> - An optional stage for algorithms that support <code>File</code> training input mode. It indicates that data is being downloaded to the ML storage volumes.</p></li>
    /// <li>
    /// <p><code>Training</code> - Training is in progress.</p></li>
    /// <li>
    /// <p><code>Uploading</code> - Training is complete and the model artifacts are being uploaded to the S3 location.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Completed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code> - The training job has completed.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Failed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The training job has failed. The reason for the failure is returned in the <code>FailureReason</code> field of <code>DescribeTrainingJobResponse</code>.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopped
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>MaxRuntimeExceeded</code> - The job stopped because it exceeded the maximum allowed runtime.</p></li>
    /// <li>
    /// <p><code>Stopped</code> - The training job has stopped.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopping
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Stopping</code> - Stopping the training job.</p></li>
    /// </ul>
    /// </dd>
    /// </dl>
    /// <p>We no longer support the following secondary statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>LaunchingMLInstances</code></p></li>
    /// <li>
    /// <p><code>PreparingTrainingStack</code></p></li>
    /// <li>
    /// <p><code>DownloadingTrainingImage</code></p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::SecondaryStatus> {
        self.status.as_ref()
    }
    /// <p>A timestamp that shows when the training job transitioned to the current secondary status state.</p>
    pub fn start_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.start_time.as_ref()
    }
    /// <p>A timestamp that shows when the training job transitioned out of this secondary status state into another secondary status state or when the training job has ended.</p>
    pub fn end_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.end_time.as_ref()
    }
    /// <p>A detailed description of the progress within a secondary status.</p>
    /// <p>SageMaker provides secondary statuses and status messages that apply to each of them:</p>
    /// <dl>
    /// <dt>
    /// Starting
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Starting the training job.</p></li>
    /// <li>
    /// <p>Launching requested ML instances.</p></li>
    /// <li>
    /// <p>Insufficient capacity error from EC2 while launching instances, retrying!</p></li>
    /// <li>
    /// <p>Launched instance was unhealthy, replacing it!</p></li>
    /// <li>
    /// <p>Preparing the instances for training.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Training
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Training image download completed. Training in progress.</p></li>
    /// </ul>
    /// </dd>
    /// </dl><important>
    /// <p>Status messages are subject to change. Therefore, we recommend not including them in code that programmatically initiates actions. For examples, don't use status messages in if statements.</p>
    /// </important>
    /// <p>To have an overview of your training job's progress, view <code>TrainingJobStatus</code> and <code>SecondaryStatus</code> in <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeTrainingJob.html">DescribeTrainingJob</a>, and <code>StatusMessage</code> together. For example, at the start of a training job, you might see the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>TrainingJobStatus</code> - InProgress</p></li>
    /// <li>
    /// <p><code>SecondaryStatus</code> - Training</p></li>
    /// <li>
    /// <p><code>StatusMessage</code> - Downloading the training image</p></li>
    /// </ul>
    pub fn status_message(&self) -> ::std::option::Option<&str> {
        self.status_message.as_deref()
    }
}
impl SecondaryStatusTransition {
    /// Creates a new builder-style object to manufacture [`SecondaryStatusTransition`](crate::types::SecondaryStatusTransition).
    pub fn builder() -> crate::types::builders::SecondaryStatusTransitionBuilder {
        crate::types::builders::SecondaryStatusTransitionBuilder::default()
    }
}

/// A builder for [`SecondaryStatusTransition`](crate::types::SecondaryStatusTransition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SecondaryStatusTransitionBuilder {
    pub(crate) status: ::std::option::Option<crate::types::SecondaryStatus>,
    pub(crate) start_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) end_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) status_message: ::std::option::Option<::std::string::String>,
}
impl SecondaryStatusTransitionBuilder {
    /// <p>Contains a secondary status information from a training job.</p>
    /// <p>Status might be one of the following secondary statuses:</p>
    /// <dl>
    /// <dt>
    /// InProgress
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Starting</code> - Starting the training job.</p></li>
    /// <li>
    /// <p><code>Downloading</code> - An optional stage for algorithms that support <code>File</code> training input mode. It indicates that data is being downloaded to the ML storage volumes.</p></li>
    /// <li>
    /// <p><code>Training</code> - Training is in progress.</p></li>
    /// <li>
    /// <p><code>Uploading</code> - Training is complete and the model artifacts are being uploaded to the S3 location.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Completed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code> - The training job has completed.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Failed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The training job has failed. The reason for the failure is returned in the <code>FailureReason</code> field of <code>DescribeTrainingJobResponse</code>.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopped
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>MaxRuntimeExceeded</code> - The job stopped because it exceeded the maximum allowed runtime.</p></li>
    /// <li>
    /// <p><code>Stopped</code> - The training job has stopped.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopping
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Stopping</code> - Stopping the training job.</p></li>
    /// </ul>
    /// </dd>
    /// </dl>
    /// <p>We no longer support the following secondary statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>LaunchingMLInstances</code></p></li>
    /// <li>
    /// <p><code>PreparingTrainingStack</code></p></li>
    /// <li>
    /// <p><code>DownloadingTrainingImage</code></p></li>
    /// </ul>
    /// This field is required.
    pub fn status(mut self, input: crate::types::SecondaryStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains a secondary status information from a training job.</p>
    /// <p>Status might be one of the following secondary statuses:</p>
    /// <dl>
    /// <dt>
    /// InProgress
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Starting</code> - Starting the training job.</p></li>
    /// <li>
    /// <p><code>Downloading</code> - An optional stage for algorithms that support <code>File</code> training input mode. It indicates that data is being downloaded to the ML storage volumes.</p></li>
    /// <li>
    /// <p><code>Training</code> - Training is in progress.</p></li>
    /// <li>
    /// <p><code>Uploading</code> - Training is complete and the model artifacts are being uploaded to the S3 location.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Completed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code> - The training job has completed.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Failed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The training job has failed. The reason for the failure is returned in the <code>FailureReason</code> field of <code>DescribeTrainingJobResponse</code>.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopped
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>MaxRuntimeExceeded</code> - The job stopped because it exceeded the maximum allowed runtime.</p></li>
    /// <li>
    /// <p><code>Stopped</code> - The training job has stopped.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopping
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Stopping</code> - Stopping the training job.</p></li>
    /// </ul>
    /// </dd>
    /// </dl>
    /// <p>We no longer support the following secondary statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>LaunchingMLInstances</code></p></li>
    /// <li>
    /// <p><code>PreparingTrainingStack</code></p></li>
    /// <li>
    /// <p><code>DownloadingTrainingImage</code></p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::SecondaryStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>Contains a secondary status information from a training job.</p>
    /// <p>Status might be one of the following secondary statuses:</p>
    /// <dl>
    /// <dt>
    /// InProgress
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Starting</code> - Starting the training job.</p></li>
    /// <li>
    /// <p><code>Downloading</code> - An optional stage for algorithms that support <code>File</code> training input mode. It indicates that data is being downloaded to the ML storage volumes.</p></li>
    /// <li>
    /// <p><code>Training</code> - Training is in progress.</p></li>
    /// <li>
    /// <p><code>Uploading</code> - Training is complete and the model artifacts are being uploaded to the S3 location.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Completed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Completed</code> - The training job has completed.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Failed
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Failed</code> - The training job has failed. The reason for the failure is returned in the <code>FailureReason</code> field of <code>DescribeTrainingJobResponse</code>.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopped
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>MaxRuntimeExceeded</code> - The job stopped because it exceeded the maximum allowed runtime.</p></li>
    /// <li>
    /// <p><code>Stopped</code> - The training job has stopped.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Stopping
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p><code>Stopping</code> - Stopping the training job.</p></li>
    /// </ul>
    /// </dd>
    /// </dl>
    /// <p>We no longer support the following secondary statuses:</p>
    /// <ul>
    /// <li>
    /// <p><code>LaunchingMLInstances</code></p></li>
    /// <li>
    /// <p><code>PreparingTrainingStack</code></p></li>
    /// <li>
    /// <p><code>DownloadingTrainingImage</code></p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::SecondaryStatus> {
        &self.status
    }
    /// <p>A timestamp that shows when the training job transitioned to the current secondary status state.</p>
    /// This field is required.
    pub fn start_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.start_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that shows when the training job transitioned to the current secondary status state.</p>
    pub fn set_start_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.start_time = input;
        self
    }
    /// <p>A timestamp that shows when the training job transitioned to the current secondary status state.</p>
    pub fn get_start_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.start_time
    }
    /// <p>A timestamp that shows when the training job transitioned out of this secondary status state into another secondary status state or when the training job has ended.</p>
    pub fn end_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.end_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that shows when the training job transitioned out of this secondary status state into another secondary status state or when the training job has ended.</p>
    pub fn set_end_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.end_time = input;
        self
    }
    /// <p>A timestamp that shows when the training job transitioned out of this secondary status state into another secondary status state or when the training job has ended.</p>
    pub fn get_end_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.end_time
    }
    /// <p>A detailed description of the progress within a secondary status.</p>
    /// <p>SageMaker provides secondary statuses and status messages that apply to each of them:</p>
    /// <dl>
    /// <dt>
    /// Starting
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Starting the training job.</p></li>
    /// <li>
    /// <p>Launching requested ML instances.</p></li>
    /// <li>
    /// <p>Insufficient capacity error from EC2 while launching instances, retrying!</p></li>
    /// <li>
    /// <p>Launched instance was unhealthy, replacing it!</p></li>
    /// <li>
    /// <p>Preparing the instances for training.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Training
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Training image download completed. Training in progress.</p></li>
    /// </ul>
    /// </dd>
    /// </dl><important>
    /// <p>Status messages are subject to change. Therefore, we recommend not including them in code that programmatically initiates actions. For examples, don't use status messages in if statements.</p>
    /// </important>
    /// <p>To have an overview of your training job's progress, view <code>TrainingJobStatus</code> and <code>SecondaryStatus</code> in <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeTrainingJob.html">DescribeTrainingJob</a>, and <code>StatusMessage</code> together. For example, at the start of a training job, you might see the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>TrainingJobStatus</code> - InProgress</p></li>
    /// <li>
    /// <p><code>SecondaryStatus</code> - Training</p></li>
    /// <li>
    /// <p><code>StatusMessage</code> - Downloading the training image</p></li>
    /// </ul>
    pub fn status_message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status_message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A detailed description of the progress within a secondary status.</p>
    /// <p>SageMaker provides secondary statuses and status messages that apply to each of them:</p>
    /// <dl>
    /// <dt>
    /// Starting
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Starting the training job.</p></li>
    /// <li>
    /// <p>Launching requested ML instances.</p></li>
    /// <li>
    /// <p>Insufficient capacity error from EC2 while launching instances, retrying!</p></li>
    /// <li>
    /// <p>Launched instance was unhealthy, replacing it!</p></li>
    /// <li>
    /// <p>Preparing the instances for training.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Training
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Training image download completed. Training in progress.</p></li>
    /// </ul>
    /// </dd>
    /// </dl><important>
    /// <p>Status messages are subject to change. Therefore, we recommend not including them in code that programmatically initiates actions. For examples, don't use status messages in if statements.</p>
    /// </important>
    /// <p>To have an overview of your training job's progress, view <code>TrainingJobStatus</code> and <code>SecondaryStatus</code> in <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeTrainingJob.html">DescribeTrainingJob</a>, and <code>StatusMessage</code> together. For example, at the start of a training job, you might see the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>TrainingJobStatus</code> - InProgress</p></li>
    /// <li>
    /// <p><code>SecondaryStatus</code> - Training</p></li>
    /// <li>
    /// <p><code>StatusMessage</code> - Downloading the training image</p></li>
    /// </ul>
    pub fn set_status_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status_message = input;
        self
    }
    /// <p>A detailed description of the progress within a secondary status.</p>
    /// <p>SageMaker provides secondary statuses and status messages that apply to each of them:</p>
    /// <dl>
    /// <dt>
    /// Starting
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Starting the training job.</p></li>
    /// <li>
    /// <p>Launching requested ML instances.</p></li>
    /// <li>
    /// <p>Insufficient capacity error from EC2 while launching instances, retrying!</p></li>
    /// <li>
    /// <p>Launched instance was unhealthy, replacing it!</p></li>
    /// <li>
    /// <p>Preparing the instances for training.</p></li>
    /// </ul>
    /// </dd>
    /// <dt>
    /// Training
    /// </dt>
    /// <dd>
    /// <ul>
    /// <li>
    /// <p>Training image download completed. Training in progress.</p></li>
    /// </ul>
    /// </dd>
    /// </dl><important>
    /// <p>Status messages are subject to change. Therefore, we recommend not including them in code that programmatically initiates actions. For examples, don't use status messages in if statements.</p>
    /// </important>
    /// <p>To have an overview of your training job's progress, view <code>TrainingJobStatus</code> and <code>SecondaryStatus</code> in <a href="https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_DescribeTrainingJob.html">DescribeTrainingJob</a>, and <code>StatusMessage</code> together. For example, at the start of a training job, you might see the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>TrainingJobStatus</code> - InProgress</p></li>
    /// <li>
    /// <p><code>SecondaryStatus</code> - Training</p></li>
    /// <li>
    /// <p><code>StatusMessage</code> - Downloading the training image</p></li>
    /// </ul>
    pub fn get_status_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.status_message
    }
    /// Consumes the builder and constructs a [`SecondaryStatusTransition`](crate::types::SecondaryStatusTransition).
    pub fn build(self) -> crate::types::SecondaryStatusTransition {
        crate::types::SecondaryStatusTransition {
            status: self.status,
            start_time: self.start_time,
            end_time: self.end_time,
            status_message: self.status_message,
        }
    }
}
