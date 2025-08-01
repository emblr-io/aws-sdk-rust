// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateApplicationOutput {
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> that's assigned to an application resource and uniquely identifies it across all Amazon Web Services Regions. Format is <code>arn:aws:gameliftstreams:\[AWS Region\]:\[AWS account\]:application/\[resource ID\]</code>.</p>
    pub arn: ::std::string::String,
    /// <p>A human-readable label for the application. You can edit this value.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Configuration settings that identify the operating system for an application resource. This can also include a compatibility layer and other drivers.</p>
    /// <p>A runtime environment can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>For Linux applications</p>
    /// <ul>
    /// <li>
    /// <p>Ubuntu 22.04 LTS (<code>Type=UBUNTU, Version=22_04_LTS</code>)</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For Windows applications</p>
    /// <ul>
    /// <li>
    /// <p>Microsoft Windows Server 2022 Base (<code>Type=WINDOWS, Version=2022</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-5 (<code>Type=PROTON, Version=20241007</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-2c (<code>Type=PROTON, Version=20230704</code>)</p></li>
    /// </ul></li>
    /// </ul>
    pub runtime_environment: ::std::option::Option<crate::types::RuntimeEnvironment>,
    /// <p>The path and file name of the executable file that launches the content for streaming.</p>
    pub executable_path: ::std::option::Option<::std::string::String>,
    /// <p>Locations of log files that your content generates during a stream session. Amazon GameLift Streams uploads log files to the Amazon S3 bucket that you specify in <code>ApplicationLogOutputUri</code> at the end of a stream session. To retrieve stored log files, call <a href="https://docs.aws.amazon.com/gameliftstreams/latest/apireference/API_GetStreamSession.html">GetStreamSession</a> and get the <code>LogFileLocationUri</code>.</p>
    pub application_log_paths: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An Amazon S3 URI to a bucket where you would like Amazon GameLift Streams to save application logs. Required if you specify one or more <code>ApplicationLogPaths</code>.</p>
    pub application_log_output_uri: ::std::option::Option<::std::string::String>,
    /// <p>The original Amazon S3 location of uploaded stream content for the application.</p>
    pub application_source_uri: ::std::option::Option<::std::string::String>,
    /// <p>A unique ID value that is assigned to the resource when it's created. Format example: <code>a-9ZY8X7Wv6</code>.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The current status of the application resource. Possible statuses include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>INITIALIZED</code>: Amazon GameLift Streams has received the request and is initiating the work flow to create an application.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code>: The create application work flow is in process. Amazon GameLift Streams is copying the content and caching for future deployment in a stream group.</p></li>
    /// <li>
    /// <p><code>READY</code>: The application is ready to deploy in a stream group.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: An error occurred when setting up the application. See <code>StatusReason</code> for more information.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Amazon GameLift Streams is in the process of deleting the application.</p></li>
    /// </ul>
    pub status: ::std::option::Option<crate::types::ApplicationStatus>,
    /// <p>A short description of the status reason when the application is in <code>ERROR</code> status.</p>
    pub status_reason: ::std::option::Option<crate::types::ApplicationStatusReason>,
    /// <p>A set of replication statuses for each location.</p>
    pub replication_statuses: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationStatus>>,
    /// <p>A timestamp that indicates when this resource was created. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A timestamp that indicates when this resource was last updated. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A newly created application is not associated to any stream groups. This value is empty.</p>
    pub associated_stream_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl CreateApplicationOutput {
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> that's assigned to an application resource and uniquely identifies it across all Amazon Web Services Regions. Format is <code>arn:aws:gameliftstreams:\[AWS Region\]:\[AWS account\]:application/\[resource ID\]</code>.</p>
    pub fn arn(&self) -> &str {
        use std::ops::Deref;
        self.arn.deref()
    }
    /// <p>A human-readable label for the application. You can edit this value.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Configuration settings that identify the operating system for an application resource. This can also include a compatibility layer and other drivers.</p>
    /// <p>A runtime environment can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>For Linux applications</p>
    /// <ul>
    /// <li>
    /// <p>Ubuntu 22.04 LTS (<code>Type=UBUNTU, Version=22_04_LTS</code>)</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For Windows applications</p>
    /// <ul>
    /// <li>
    /// <p>Microsoft Windows Server 2022 Base (<code>Type=WINDOWS, Version=2022</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-5 (<code>Type=PROTON, Version=20241007</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-2c (<code>Type=PROTON, Version=20230704</code>)</p></li>
    /// </ul></li>
    /// </ul>
    pub fn runtime_environment(&self) -> ::std::option::Option<&crate::types::RuntimeEnvironment> {
        self.runtime_environment.as_ref()
    }
    /// <p>The path and file name of the executable file that launches the content for streaming.</p>
    pub fn executable_path(&self) -> ::std::option::Option<&str> {
        self.executable_path.as_deref()
    }
    /// <p>Locations of log files that your content generates during a stream session. Amazon GameLift Streams uploads log files to the Amazon S3 bucket that you specify in <code>ApplicationLogOutputUri</code> at the end of a stream session. To retrieve stored log files, call <a href="https://docs.aws.amazon.com/gameliftstreams/latest/apireference/API_GetStreamSession.html">GetStreamSession</a> and get the <code>LogFileLocationUri</code>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.application_log_paths.is_none()`.
    pub fn application_log_paths(&self) -> &[::std::string::String] {
        self.application_log_paths.as_deref().unwrap_or_default()
    }
    /// <p>An Amazon S3 URI to a bucket where you would like Amazon GameLift Streams to save application logs. Required if you specify one or more <code>ApplicationLogPaths</code>.</p>
    pub fn application_log_output_uri(&self) -> ::std::option::Option<&str> {
        self.application_log_output_uri.as_deref()
    }
    /// <p>The original Amazon S3 location of uploaded stream content for the application.</p>
    pub fn application_source_uri(&self) -> ::std::option::Option<&str> {
        self.application_source_uri.as_deref()
    }
    /// <p>A unique ID value that is assigned to the resource when it's created. Format example: <code>a-9ZY8X7Wv6</code>.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The current status of the application resource. Possible statuses include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>INITIALIZED</code>: Amazon GameLift Streams has received the request and is initiating the work flow to create an application.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code>: The create application work flow is in process. Amazon GameLift Streams is copying the content and caching for future deployment in a stream group.</p></li>
    /// <li>
    /// <p><code>READY</code>: The application is ready to deploy in a stream group.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: An error occurred when setting up the application. See <code>StatusReason</code> for more information.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Amazon GameLift Streams is in the process of deleting the application.</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&crate::types::ApplicationStatus> {
        self.status.as_ref()
    }
    /// <p>A short description of the status reason when the application is in <code>ERROR</code> status.</p>
    pub fn status_reason(&self) -> ::std::option::Option<&crate::types::ApplicationStatusReason> {
        self.status_reason.as_ref()
    }
    /// <p>A set of replication statuses for each location.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.replication_statuses.is_none()`.
    pub fn replication_statuses(&self) -> &[crate::types::ReplicationStatus] {
        self.replication_statuses.as_deref().unwrap_or_default()
    }
    /// <p>A timestamp that indicates when this resource was created. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>A timestamp that indicates when this resource was last updated. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub fn last_updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated_at.as_ref()
    }
    /// <p>A newly created application is not associated to any stream groups. This value is empty.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.associated_stream_groups.is_none()`.
    pub fn associated_stream_groups(&self) -> &[::std::string::String] {
        self.associated_stream_groups.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for CreateApplicationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateApplicationOutput {
    /// Creates a new builder-style object to manufacture [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
    pub fn builder() -> crate::operation::create_application::builders::CreateApplicationOutputBuilder {
        crate::operation::create_application::builders::CreateApplicationOutputBuilder::default()
    }
}

/// A builder for [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateApplicationOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) runtime_environment: ::std::option::Option<crate::types::RuntimeEnvironment>,
    pub(crate) executable_path: ::std::option::Option<::std::string::String>,
    pub(crate) application_log_paths: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) application_log_output_uri: ::std::option::Option<::std::string::String>,
    pub(crate) application_source_uri: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::ApplicationStatus>,
    pub(crate) status_reason: ::std::option::Option<crate::types::ApplicationStatusReason>,
    pub(crate) replication_statuses: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationStatus>>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) last_updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) associated_stream_groups: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    _request_id: Option<String>,
}
impl CreateApplicationOutputBuilder {
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> that's assigned to an application resource and uniquely identifies it across all Amazon Web Services Regions. Format is <code>arn:aws:gameliftstreams:\[AWS Region\]:\[AWS account\]:application/\[resource ID\]</code>.</p>
    /// This field is required.
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> that's assigned to an application resource and uniquely identifies it across all Amazon Web Services Regions. Format is <code>arn:aws:gameliftstreams:\[AWS Region\]:\[AWS account\]:application/\[resource ID\]</code>.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/reference-arns.html">Amazon Resource Name (ARN)</a> that's assigned to an application resource and uniquely identifies it across all Amazon Web Services Regions. Format is <code>arn:aws:gameliftstreams:\[AWS Region\]:\[AWS account\]:application/\[resource ID\]</code>.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>A human-readable label for the application. You can edit this value.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A human-readable label for the application. You can edit this value.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A human-readable label for the application. You can edit this value.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Configuration settings that identify the operating system for an application resource. This can also include a compatibility layer and other drivers.</p>
    /// <p>A runtime environment can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>For Linux applications</p>
    /// <ul>
    /// <li>
    /// <p>Ubuntu 22.04 LTS (<code>Type=UBUNTU, Version=22_04_LTS</code>)</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For Windows applications</p>
    /// <ul>
    /// <li>
    /// <p>Microsoft Windows Server 2022 Base (<code>Type=WINDOWS, Version=2022</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-5 (<code>Type=PROTON, Version=20241007</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-2c (<code>Type=PROTON, Version=20230704</code>)</p></li>
    /// </ul></li>
    /// </ul>
    pub fn runtime_environment(mut self, input: crate::types::RuntimeEnvironment) -> Self {
        self.runtime_environment = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configuration settings that identify the operating system for an application resource. This can also include a compatibility layer and other drivers.</p>
    /// <p>A runtime environment can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>For Linux applications</p>
    /// <ul>
    /// <li>
    /// <p>Ubuntu 22.04 LTS (<code>Type=UBUNTU, Version=22_04_LTS</code>)</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For Windows applications</p>
    /// <ul>
    /// <li>
    /// <p>Microsoft Windows Server 2022 Base (<code>Type=WINDOWS, Version=2022</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-5 (<code>Type=PROTON, Version=20241007</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-2c (<code>Type=PROTON, Version=20230704</code>)</p></li>
    /// </ul></li>
    /// </ul>
    pub fn set_runtime_environment(mut self, input: ::std::option::Option<crate::types::RuntimeEnvironment>) -> Self {
        self.runtime_environment = input;
        self
    }
    /// <p>Configuration settings that identify the operating system for an application resource. This can also include a compatibility layer and other drivers.</p>
    /// <p>A runtime environment can be one of the following:</p>
    /// <ul>
    /// <li>
    /// <p>For Linux applications</p>
    /// <ul>
    /// <li>
    /// <p>Ubuntu 22.04 LTS (<code>Type=UBUNTU, Version=22_04_LTS</code>)</p></li>
    /// </ul></li>
    /// <li>
    /// <p>For Windows applications</p>
    /// <ul>
    /// <li>
    /// <p>Microsoft Windows Server 2022 Base (<code>Type=WINDOWS, Version=2022</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-5 (<code>Type=PROTON, Version=20241007</code>)</p></li>
    /// <li>
    /// <p>Proton 8.0-2c (<code>Type=PROTON, Version=20230704</code>)</p></li>
    /// </ul></li>
    /// </ul>
    pub fn get_runtime_environment(&self) -> &::std::option::Option<crate::types::RuntimeEnvironment> {
        &self.runtime_environment
    }
    /// <p>The path and file name of the executable file that launches the content for streaming.</p>
    pub fn executable_path(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.executable_path = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The path and file name of the executable file that launches the content for streaming.</p>
    pub fn set_executable_path(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.executable_path = input;
        self
    }
    /// <p>The path and file name of the executable file that launches the content for streaming.</p>
    pub fn get_executable_path(&self) -> &::std::option::Option<::std::string::String> {
        &self.executable_path
    }
    /// Appends an item to `application_log_paths`.
    ///
    /// To override the contents of this collection use [`set_application_log_paths`](Self::set_application_log_paths).
    ///
    /// <p>Locations of log files that your content generates during a stream session. Amazon GameLift Streams uploads log files to the Amazon S3 bucket that you specify in <code>ApplicationLogOutputUri</code> at the end of a stream session. To retrieve stored log files, call <a href="https://docs.aws.amazon.com/gameliftstreams/latest/apireference/API_GetStreamSession.html">GetStreamSession</a> and get the <code>LogFileLocationUri</code>.</p>
    pub fn application_log_paths(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.application_log_paths.unwrap_or_default();
        v.push(input.into());
        self.application_log_paths = ::std::option::Option::Some(v);
        self
    }
    /// <p>Locations of log files that your content generates during a stream session. Amazon GameLift Streams uploads log files to the Amazon S3 bucket that you specify in <code>ApplicationLogOutputUri</code> at the end of a stream session. To retrieve stored log files, call <a href="https://docs.aws.amazon.com/gameliftstreams/latest/apireference/API_GetStreamSession.html">GetStreamSession</a> and get the <code>LogFileLocationUri</code>.</p>
    pub fn set_application_log_paths(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.application_log_paths = input;
        self
    }
    /// <p>Locations of log files that your content generates during a stream session. Amazon GameLift Streams uploads log files to the Amazon S3 bucket that you specify in <code>ApplicationLogOutputUri</code> at the end of a stream session. To retrieve stored log files, call <a href="https://docs.aws.amazon.com/gameliftstreams/latest/apireference/API_GetStreamSession.html">GetStreamSession</a> and get the <code>LogFileLocationUri</code>.</p>
    pub fn get_application_log_paths(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.application_log_paths
    }
    /// <p>An Amazon S3 URI to a bucket where you would like Amazon GameLift Streams to save application logs. Required if you specify one or more <code>ApplicationLogPaths</code>.</p>
    pub fn application_log_output_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_log_output_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An Amazon S3 URI to a bucket where you would like Amazon GameLift Streams to save application logs. Required if you specify one or more <code>ApplicationLogPaths</code>.</p>
    pub fn set_application_log_output_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_log_output_uri = input;
        self
    }
    /// <p>An Amazon S3 URI to a bucket where you would like Amazon GameLift Streams to save application logs. Required if you specify one or more <code>ApplicationLogPaths</code>.</p>
    pub fn get_application_log_output_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_log_output_uri
    }
    /// <p>The original Amazon S3 location of uploaded stream content for the application.</p>
    pub fn application_source_uri(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_source_uri = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The original Amazon S3 location of uploaded stream content for the application.</p>
    pub fn set_application_source_uri(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_source_uri = input;
        self
    }
    /// <p>The original Amazon S3 location of uploaded stream content for the application.</p>
    pub fn get_application_source_uri(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_source_uri
    }
    /// <p>A unique ID value that is assigned to the resource when it's created. Format example: <code>a-9ZY8X7Wv6</code>.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique ID value that is assigned to the resource when it's created. Format example: <code>a-9ZY8X7Wv6</code>.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>A unique ID value that is assigned to the resource when it's created. Format example: <code>a-9ZY8X7Wv6</code>.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The current status of the application resource. Possible statuses include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>INITIALIZED</code>: Amazon GameLift Streams has received the request and is initiating the work flow to create an application.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code>: The create application work flow is in process. Amazon GameLift Streams is copying the content and caching for future deployment in a stream group.</p></li>
    /// <li>
    /// <p><code>READY</code>: The application is ready to deploy in a stream group.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: An error occurred when setting up the application. See <code>StatusReason</code> for more information.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Amazon GameLift Streams is in the process of deleting the application.</p></li>
    /// </ul>
    pub fn status(mut self, input: crate::types::ApplicationStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The current status of the application resource. Possible statuses include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>INITIALIZED</code>: Amazon GameLift Streams has received the request and is initiating the work flow to create an application.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code>: The create application work flow is in process. Amazon GameLift Streams is copying the content and caching for future deployment in a stream group.</p></li>
    /// <li>
    /// <p><code>READY</code>: The application is ready to deploy in a stream group.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: An error occurred when setting up the application. See <code>StatusReason</code> for more information.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Amazon GameLift Streams is in the process of deleting the application.</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::ApplicationStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The current status of the application resource. Possible statuses include the following:</p>
    /// <ul>
    /// <li>
    /// <p><code>INITIALIZED</code>: Amazon GameLift Streams has received the request and is initiating the work flow to create an application.</p></li>
    /// <li>
    /// <p><code>PROCESSING</code>: The create application work flow is in process. Amazon GameLift Streams is copying the content and caching for future deployment in a stream group.</p></li>
    /// <li>
    /// <p><code>READY</code>: The application is ready to deploy in a stream group.</p></li>
    /// <li>
    /// <p><code>ERROR</code>: An error occurred when setting up the application. See <code>StatusReason</code> for more information.</p></li>
    /// <li>
    /// <p><code>DELETING</code>: Amazon GameLift Streams is in the process of deleting the application.</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::ApplicationStatus> {
        &self.status
    }
    /// <p>A short description of the status reason when the application is in <code>ERROR</code> status.</p>
    pub fn status_reason(mut self, input: crate::types::ApplicationStatusReason) -> Self {
        self.status_reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>A short description of the status reason when the application is in <code>ERROR</code> status.</p>
    pub fn set_status_reason(mut self, input: ::std::option::Option<crate::types::ApplicationStatusReason>) -> Self {
        self.status_reason = input;
        self
    }
    /// <p>A short description of the status reason when the application is in <code>ERROR</code> status.</p>
    pub fn get_status_reason(&self) -> &::std::option::Option<crate::types::ApplicationStatusReason> {
        &self.status_reason
    }
    /// Appends an item to `replication_statuses`.
    ///
    /// To override the contents of this collection use [`set_replication_statuses`](Self::set_replication_statuses).
    ///
    /// <p>A set of replication statuses for each location.</p>
    pub fn replication_statuses(mut self, input: crate::types::ReplicationStatus) -> Self {
        let mut v = self.replication_statuses.unwrap_or_default();
        v.push(input);
        self.replication_statuses = ::std::option::Option::Some(v);
        self
    }
    /// <p>A set of replication statuses for each location.</p>
    pub fn set_replication_statuses(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReplicationStatus>>) -> Self {
        self.replication_statuses = input;
        self
    }
    /// <p>A set of replication statuses for each location.</p>
    pub fn get_replication_statuses(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReplicationStatus>> {
        &self.replication_statuses
    }
    /// <p>A timestamp that indicates when this resource was created. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that indicates when this resource was created. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>A timestamp that indicates when this resource was created. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>A timestamp that indicates when this resource was last updated. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub fn last_updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>A timestamp that indicates when this resource was last updated. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub fn set_last_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated_at = input;
        self
    }
    /// <p>A timestamp that indicates when this resource was last updated. Timestamps are expressed using in ISO8601 format, such as: <code>2022-12-27T22:29:40+00:00</code> (UTC).</p>
    pub fn get_last_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated_at
    }
    /// Appends an item to `associated_stream_groups`.
    ///
    /// To override the contents of this collection use [`set_associated_stream_groups`](Self::set_associated_stream_groups).
    ///
    /// <p>A newly created application is not associated to any stream groups. This value is empty.</p>
    pub fn associated_stream_groups(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.associated_stream_groups.unwrap_or_default();
        v.push(input.into());
        self.associated_stream_groups = ::std::option::Option::Some(v);
        self
    }
    /// <p>A newly created application is not associated to any stream groups. This value is empty.</p>
    pub fn set_associated_stream_groups(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.associated_stream_groups = input;
        self
    }
    /// <p>A newly created application is not associated to any stream groups. This value is empty.</p>
    pub fn get_associated_stream_groups(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.associated_stream_groups
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateApplicationOutput`](crate::operation::create_application::CreateApplicationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`arn`](crate::operation::create_application::builders::CreateApplicationOutputBuilder::arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_application::CreateApplicationOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_application::CreateApplicationOutput {
            arn: self.arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "arn",
                    "arn was not specified but it is required when building CreateApplicationOutput",
                )
            })?,
            description: self.description,
            runtime_environment: self.runtime_environment,
            executable_path: self.executable_path,
            application_log_paths: self.application_log_paths,
            application_log_output_uri: self.application_log_output_uri,
            application_source_uri: self.application_source_uri,
            id: self.id,
            status: self.status,
            status_reason: self.status_reason,
            replication_statuses: self.replication_statuses,
            created_at: self.created_at,
            last_updated_at: self.last_updated_at,
            associated_stream_groups: self.associated_stream_groups,
            _request_id: self._request_id,
        })
    }
}
