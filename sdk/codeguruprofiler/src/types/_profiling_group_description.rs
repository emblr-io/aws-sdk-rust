// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a profiling group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ProfilingGroupDescription {
    /// <p>The name of the profiling group.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AgentOrchestrationConfig.html"> <code>AgentOrchestrationConfig</code> </a> object that indicates if the profiling group is enabled for profiled or not.</p>
    pub agent_orchestration_config: ::std::option::Option<crate::types::AgentOrchestrationConfig>,
    /// <p>The Amazon Resource Name (ARN) identifying the profiling group resource.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The time when the profiling group was created. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time when the profiling group was last updated. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>A <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ProfilingStatus.html"> <code>ProfilingStatus</code> </a> object that includes information about the last time a profile agent pinged back, the last time a profile was received, and the aggregation period and start time for the most recent aggregated profile.</p>
    pub profiling_status: ::std::option::Option<crate::types::ProfilingStatus>,
    /// <p>The compute platform of the profiling group. If it is set to <code>AWSLambda</code>, then the profiled application runs on AWS Lambda. If it is set to <code>Default</code>, then the profiled application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. The default is <code>Default</code>.</p>
    pub compute_platform: ::std::option::Option<crate::types::ComputePlatform>,
    /// <p>A list of the tags that belong to this profiling group.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ProfilingGroupDescription {
    /// <p>The name of the profiling group.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AgentOrchestrationConfig.html"> <code>AgentOrchestrationConfig</code> </a> object that indicates if the profiling group is enabled for profiled or not.</p>
    pub fn agent_orchestration_config(&self) -> ::std::option::Option<&crate::types::AgentOrchestrationConfig> {
        self.agent_orchestration_config.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) identifying the profiling group resource.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The time when the profiling group was created. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The date and time when the profiling group was last updated. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn updated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.updated_at.as_ref()
    }
    /// <p>A <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ProfilingStatus.html"> <code>ProfilingStatus</code> </a> object that includes information about the last time a profile agent pinged back, the last time a profile was received, and the aggregation period and start time for the most recent aggregated profile.</p>
    pub fn profiling_status(&self) -> ::std::option::Option<&crate::types::ProfilingStatus> {
        self.profiling_status.as_ref()
    }
    /// <p>The compute platform of the profiling group. If it is set to <code>AWSLambda</code>, then the profiled application runs on AWS Lambda. If it is set to <code>Default</code>, then the profiled application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. The default is <code>Default</code>.</p>
    pub fn compute_platform(&self) -> ::std::option::Option<&crate::types::ComputePlatform> {
        self.compute_platform.as_ref()
    }
    /// <p>A list of the tags that belong to this profiling group.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl ProfilingGroupDescription {
    /// Creates a new builder-style object to manufacture [`ProfilingGroupDescription`](crate::types::ProfilingGroupDescription).
    pub fn builder() -> crate::types::builders::ProfilingGroupDescriptionBuilder {
        crate::types::builders::ProfilingGroupDescriptionBuilder::default()
    }
}

/// A builder for [`ProfilingGroupDescription`](crate::types::ProfilingGroupDescription).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ProfilingGroupDescriptionBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) agent_orchestration_config: ::std::option::Option<crate::types::AgentOrchestrationConfig>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) updated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) profiling_status: ::std::option::Option<crate::types::ProfilingStatus>,
    pub(crate) compute_platform: ::std::option::Option<crate::types::ComputePlatform>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl ProfilingGroupDescriptionBuilder {
    /// <p>The name of the profiling group.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the profiling group.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the profiling group.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AgentOrchestrationConfig.html"> <code>AgentOrchestrationConfig</code> </a> object that indicates if the profiling group is enabled for profiled or not.</p>
    pub fn agent_orchestration_config(mut self, input: crate::types::AgentOrchestrationConfig) -> Self {
        self.agent_orchestration_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AgentOrchestrationConfig.html"> <code>AgentOrchestrationConfig</code> </a> object that indicates if the profiling group is enabled for profiled or not.</p>
    pub fn set_agent_orchestration_config(mut self, input: ::std::option::Option<crate::types::AgentOrchestrationConfig>) -> Self {
        self.agent_orchestration_config = input;
        self
    }
    /// <p>An <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_AgentOrchestrationConfig.html"> <code>AgentOrchestrationConfig</code> </a> object that indicates if the profiling group is enabled for profiled or not.</p>
    pub fn get_agent_orchestration_config(&self) -> &::std::option::Option<crate::types::AgentOrchestrationConfig> {
        &self.agent_orchestration_config
    }
    /// <p>The Amazon Resource Name (ARN) identifying the profiling group resource.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) identifying the profiling group resource.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) identifying the profiling group resource.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The time when the profiling group was created. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the profiling group was created. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The time when the profiling group was created. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The date and time when the profiling group was last updated. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn updated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.updated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the profiling group was last updated. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn set_updated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.updated_at = input;
        self
    }
    /// <p>The date and time when the profiling group was last updated. Specify using the ISO 8601 format. For example, 2020-06-01T13:15:02.001Z represents 1 millisecond past June 1, 2020 1:15:02 PM UTC.</p>
    pub fn get_updated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.updated_at
    }
    /// <p>A <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ProfilingStatus.html"> <code>ProfilingStatus</code> </a> object that includes information about the last time a profile agent pinged back, the last time a profile was received, and the aggregation period and start time for the most recent aggregated profile.</p>
    pub fn profiling_status(mut self, input: crate::types::ProfilingStatus) -> Self {
        self.profiling_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ProfilingStatus.html"> <code>ProfilingStatus</code> </a> object that includes information about the last time a profile agent pinged back, the last time a profile was received, and the aggregation period and start time for the most recent aggregated profile.</p>
    pub fn set_profiling_status(mut self, input: ::std::option::Option<crate::types::ProfilingStatus>) -> Self {
        self.profiling_status = input;
        self
    }
    /// <p>A <a href="https://docs.aws.amazon.com/codeguru/latest/profiler-api/API_ProfilingStatus.html"> <code>ProfilingStatus</code> </a> object that includes information about the last time a profile agent pinged back, the last time a profile was received, and the aggregation period and start time for the most recent aggregated profile.</p>
    pub fn get_profiling_status(&self) -> &::std::option::Option<crate::types::ProfilingStatus> {
        &self.profiling_status
    }
    /// <p>The compute platform of the profiling group. If it is set to <code>AWSLambda</code>, then the profiled application runs on AWS Lambda. If it is set to <code>Default</code>, then the profiled application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. The default is <code>Default</code>.</p>
    pub fn compute_platform(mut self, input: crate::types::ComputePlatform) -> Self {
        self.compute_platform = ::std::option::Option::Some(input);
        self
    }
    /// <p>The compute platform of the profiling group. If it is set to <code>AWSLambda</code>, then the profiled application runs on AWS Lambda. If it is set to <code>Default</code>, then the profiled application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. The default is <code>Default</code>.</p>
    pub fn set_compute_platform(mut self, input: ::std::option::Option<crate::types::ComputePlatform>) -> Self {
        self.compute_platform = input;
        self
    }
    /// <p>The compute platform of the profiling group. If it is set to <code>AWSLambda</code>, then the profiled application runs on AWS Lambda. If it is set to <code>Default</code>, then the profiled application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. The default is <code>Default</code>.</p>
    pub fn get_compute_platform(&self) -> &::std::option::Option<crate::types::ComputePlatform> {
        &self.compute_platform
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of the tags that belong to this profiling group.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of the tags that belong to this profiling group.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of the tags that belong to this profiling group.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`ProfilingGroupDescription`](crate::types::ProfilingGroupDescription).
    pub fn build(self) -> crate::types::ProfilingGroupDescription {
        crate::types::ProfilingGroupDescription {
            name: self.name,
            agent_orchestration_config: self.agent_orchestration_config,
            arn: self.arn,
            created_at: self.created_at,
            updated_at: self.updated_at,
            profiling_status: self.profiling_status,
            compute_platform: self.compute_platform,
            tags: self.tags,
        }
    }
}
