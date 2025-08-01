// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteAgentVersionInput {
    /// <p>The unique identifier of the agent that the version belongs to.</p>
    pub agent_id: ::std::option::Option<::std::string::String>,
    /// <p>The version of the agent to delete.</p>
    pub agent_version: ::std::option::Option<::std::string::String>,
    /// <p>By default, this value is <code>false</code> and deletion is stopped if the resource is in use. If you set it to <code>true</code>, the resource will be deleted even if the resource is in use.</p>
    pub skip_resource_in_use_check: ::std::option::Option<bool>,
}
impl DeleteAgentVersionInput {
    /// <p>The unique identifier of the agent that the version belongs to.</p>
    pub fn agent_id(&self) -> ::std::option::Option<&str> {
        self.agent_id.as_deref()
    }
    /// <p>The version of the agent to delete.</p>
    pub fn agent_version(&self) -> ::std::option::Option<&str> {
        self.agent_version.as_deref()
    }
    /// <p>By default, this value is <code>false</code> and deletion is stopped if the resource is in use. If you set it to <code>true</code>, the resource will be deleted even if the resource is in use.</p>
    pub fn skip_resource_in_use_check(&self) -> ::std::option::Option<bool> {
        self.skip_resource_in_use_check
    }
}
impl DeleteAgentVersionInput {
    /// Creates a new builder-style object to manufacture [`DeleteAgentVersionInput`](crate::operation::delete_agent_version::DeleteAgentVersionInput).
    pub fn builder() -> crate::operation::delete_agent_version::builders::DeleteAgentVersionInputBuilder {
        crate::operation::delete_agent_version::builders::DeleteAgentVersionInputBuilder::default()
    }
}

/// A builder for [`DeleteAgentVersionInput`](crate::operation::delete_agent_version::DeleteAgentVersionInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteAgentVersionInputBuilder {
    pub(crate) agent_id: ::std::option::Option<::std::string::String>,
    pub(crate) agent_version: ::std::option::Option<::std::string::String>,
    pub(crate) skip_resource_in_use_check: ::std::option::Option<bool>,
}
impl DeleteAgentVersionInputBuilder {
    /// <p>The unique identifier of the agent that the version belongs to.</p>
    /// This field is required.
    pub fn agent_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the agent that the version belongs to.</p>
    pub fn set_agent_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_id = input;
        self
    }
    /// <p>The unique identifier of the agent that the version belongs to.</p>
    pub fn get_agent_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_id
    }
    /// <p>The version of the agent to delete.</p>
    /// This field is required.
    pub fn agent_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agent_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the agent to delete.</p>
    pub fn set_agent_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agent_version = input;
        self
    }
    /// <p>The version of the agent to delete.</p>
    pub fn get_agent_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.agent_version
    }
    /// <p>By default, this value is <code>false</code> and deletion is stopped if the resource is in use. If you set it to <code>true</code>, the resource will be deleted even if the resource is in use.</p>
    pub fn skip_resource_in_use_check(mut self, input: bool) -> Self {
        self.skip_resource_in_use_check = ::std::option::Option::Some(input);
        self
    }
    /// <p>By default, this value is <code>false</code> and deletion is stopped if the resource is in use. If you set it to <code>true</code>, the resource will be deleted even if the resource is in use.</p>
    pub fn set_skip_resource_in_use_check(mut self, input: ::std::option::Option<bool>) -> Self {
        self.skip_resource_in_use_check = input;
        self
    }
    /// <p>By default, this value is <code>false</code> and deletion is stopped if the resource is in use. If you set it to <code>true</code>, the resource will be deleted even if the resource is in use.</p>
    pub fn get_skip_resource_in_use_check(&self) -> &::std::option::Option<bool> {
        &self.skip_resource_in_use_check
    }
    /// Consumes the builder and constructs a [`DeleteAgentVersionInput`](crate::operation::delete_agent_version::DeleteAgentVersionInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_agent_version::DeleteAgentVersionInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_agent_version::DeleteAgentVersionInput {
            agent_id: self.agent_id,
            agent_version: self.agent_version,
            skip_resource_in_use_check: self.skip_resource_in_use_check,
        })
    }
}
