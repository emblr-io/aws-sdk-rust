// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The structure representing the createProfiliingGroupRequest.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateProfilingGroupInput {
    /// <p>The name of the profiling group to create.</p>
    pub profiling_group_name: ::std::option::Option<::std::string::String>,
    /// <p>The compute platform of the profiling group. Use <code>AWSLambda</code> if your application runs on AWS Lambda. Use <code>Default</code> if your application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, <code>Default</code> is used.</p>
    pub compute_platform: ::std::option::Option<crate::types::ComputePlatform>,
    /// <p>Amazon CodeGuru Profiler uses this universally unique identifier (UUID) to prevent the accidental creation of duplicate profiling groups if there are failures and retries.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Specifies whether profiling is enabled or disabled for the created profiling group.</p>
    pub agent_orchestration_config: ::std::option::Option<crate::types::AgentOrchestrationConfig>,
    /// <p>A list of tags to add to the created profiling group.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateProfilingGroupInput {
    /// <p>The name of the profiling group to create.</p>
    pub fn profiling_group_name(&self) -> ::std::option::Option<&str> {
        self.profiling_group_name.as_deref()
    }
    /// <p>The compute platform of the profiling group. Use <code>AWSLambda</code> if your application runs on AWS Lambda. Use <code>Default</code> if your application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, <code>Default</code> is used.</p>
    pub fn compute_platform(&self) -> ::std::option::Option<&crate::types::ComputePlatform> {
        self.compute_platform.as_ref()
    }
    /// <p>Amazon CodeGuru Profiler uses this universally unique identifier (UUID) to prevent the accidental creation of duplicate profiling groups if there are failures and retries.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Specifies whether profiling is enabled or disabled for the created profiling group.</p>
    pub fn agent_orchestration_config(&self) -> ::std::option::Option<&crate::types::AgentOrchestrationConfig> {
        self.agent_orchestration_config.as_ref()
    }
    /// <p>A list of tags to add to the created profiling group.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateProfilingGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateProfilingGroupInput`](crate::operation::create_profiling_group::CreateProfilingGroupInput).
    pub fn builder() -> crate::operation::create_profiling_group::builders::CreateProfilingGroupInputBuilder {
        crate::operation::create_profiling_group::builders::CreateProfilingGroupInputBuilder::default()
    }
}

/// A builder for [`CreateProfilingGroupInput`](crate::operation::create_profiling_group::CreateProfilingGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateProfilingGroupInputBuilder {
    pub(crate) profiling_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) compute_platform: ::std::option::Option<crate::types::ComputePlatform>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) agent_orchestration_config: ::std::option::Option<crate::types::AgentOrchestrationConfig>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateProfilingGroupInputBuilder {
    /// <p>The name of the profiling group to create.</p>
    /// This field is required.
    pub fn profiling_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.profiling_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the profiling group to create.</p>
    pub fn set_profiling_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.profiling_group_name = input;
        self
    }
    /// <p>The name of the profiling group to create.</p>
    pub fn get_profiling_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.profiling_group_name
    }
    /// <p>The compute platform of the profiling group. Use <code>AWSLambda</code> if your application runs on AWS Lambda. Use <code>Default</code> if your application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, <code>Default</code> is used.</p>
    pub fn compute_platform(mut self, input: crate::types::ComputePlatform) -> Self {
        self.compute_platform = ::std::option::Option::Some(input);
        self
    }
    /// <p>The compute platform of the profiling group. Use <code>AWSLambda</code> if your application runs on AWS Lambda. Use <code>Default</code> if your application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, <code>Default</code> is used.</p>
    pub fn set_compute_platform(mut self, input: ::std::option::Option<crate::types::ComputePlatform>) -> Self {
        self.compute_platform = input;
        self
    }
    /// <p>The compute platform of the profiling group. Use <code>AWSLambda</code> if your application runs on AWS Lambda. Use <code>Default</code> if your application runs on a compute platform that is not AWS Lambda, such an Amazon EC2 instance, an on-premises server, or a different platform. If not specified, <code>Default</code> is used.</p>
    pub fn get_compute_platform(&self) -> &::std::option::Option<crate::types::ComputePlatform> {
        &self.compute_platform
    }
    /// <p>Amazon CodeGuru Profiler uses this universally unique identifier (UUID) to prevent the accidental creation of duplicate profiling groups if there are failures and retries.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon CodeGuru Profiler uses this universally unique identifier (UUID) to prevent the accidental creation of duplicate profiling groups if there are failures and retries.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Amazon CodeGuru Profiler uses this universally unique identifier (UUID) to prevent the accidental creation of duplicate profiling groups if there are failures and retries.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Specifies whether profiling is enabled or disabled for the created profiling group.</p>
    pub fn agent_orchestration_config(mut self, input: crate::types::AgentOrchestrationConfig) -> Self {
        self.agent_orchestration_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether profiling is enabled or disabled for the created profiling group.</p>
    pub fn set_agent_orchestration_config(mut self, input: ::std::option::Option<crate::types::AgentOrchestrationConfig>) -> Self {
        self.agent_orchestration_config = input;
        self
    }
    /// <p>Specifies whether profiling is enabled or disabled for the created profiling group.</p>
    pub fn get_agent_orchestration_config(&self) -> &::std::option::Option<crate::types::AgentOrchestrationConfig> {
        &self.agent_orchestration_config
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags to add to the created profiling group.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A list of tags to add to the created profiling group.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags to add to the created profiling group.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateProfilingGroupInput`](crate::operation::create_profiling_group::CreateProfilingGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_profiling_group::CreateProfilingGroupInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_profiling_group::CreateProfilingGroupInput {
            profiling_group_name: self.profiling_group_name,
            compute_platform: self.compute_platform,
            client_token: self.client_token,
            agent_orchestration_config: self.agent_orchestration_config,
            tags: self.tags,
        })
    }
}
