// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes a command.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Command {
    /// <p>The command ID.</p>
    pub command_id: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the instance where the command was executed.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The command deployment ID.</p>
    pub deployment_id: ::std::option::Option<::std::string::String>,
    /// <p>Date and time when the command was run.</p>
    pub created_at: ::std::option::Option<::std::string::String>,
    /// <p>Date and time when the command was acknowledged.</p>
    pub acknowledged_at: ::std::option::Option<::std::string::String>,
    /// <p>Date when the command completed.</p>
    pub completed_at: ::std::option::Option<::std::string::String>,
    /// <p>The command status:</p>
    /// <ul>
    /// <li>
    /// <p>failed</p></li>
    /// <li>
    /// <p>successful</p></li>
    /// <li>
    /// <p>skipped</p></li>
    /// <li>
    /// <p>pending</p></li>
    /// </ul>
    pub status: ::std::option::Option<::std::string::String>,
    /// <p>The command exit code.</p>
    pub exit_code: ::std::option::Option<i32>,
    /// <p>The URL of the command log.</p>
    pub log_url: ::std::option::Option<::std::string::String>,
    /// <p>The command type:</p>
    /// <ul>
    /// <li>
    /// <p><code>configure</code></p></li>
    /// <li>
    /// <p><code>deploy</code></p></li>
    /// <li>
    /// <p><code>execute_recipes</code></p></li>
    /// <li>
    /// <p><code>install_dependencies</code></p></li>
    /// <li>
    /// <p><code>restart</code></p></li>
    /// <li>
    /// <p><code>rollback</code></p></li>
    /// <li>
    /// <p><code>setup</code></p></li>
    /// <li>
    /// <p><code>start</code></p></li>
    /// <li>
    /// <p><code>stop</code></p></li>
    /// <li>
    /// <p><code>undeploy</code></p></li>
    /// <li>
    /// <p><code>update_custom_cookbooks</code></p></li>
    /// <li>
    /// <p><code>update_dependencies</code></p></li>
    /// </ul>
    pub r#type: ::std::option::Option<::std::string::String>,
}
impl Command {
    /// <p>The command ID.</p>
    pub fn command_id(&self) -> ::std::option::Option<&str> {
        self.command_id.as_deref()
    }
    /// <p>The ID of the instance where the command was executed.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The command deployment ID.</p>
    pub fn deployment_id(&self) -> ::std::option::Option<&str> {
        self.deployment_id.as_deref()
    }
    /// <p>Date and time when the command was run.</p>
    pub fn created_at(&self) -> ::std::option::Option<&str> {
        self.created_at.as_deref()
    }
    /// <p>Date and time when the command was acknowledged.</p>
    pub fn acknowledged_at(&self) -> ::std::option::Option<&str> {
        self.acknowledged_at.as_deref()
    }
    /// <p>Date when the command completed.</p>
    pub fn completed_at(&self) -> ::std::option::Option<&str> {
        self.completed_at.as_deref()
    }
    /// <p>The command status:</p>
    /// <ul>
    /// <li>
    /// <p>failed</p></li>
    /// <li>
    /// <p>successful</p></li>
    /// <li>
    /// <p>skipped</p></li>
    /// <li>
    /// <p>pending</p></li>
    /// </ul>
    pub fn status(&self) -> ::std::option::Option<&str> {
        self.status.as_deref()
    }
    /// <p>The command exit code.</p>
    pub fn exit_code(&self) -> ::std::option::Option<i32> {
        self.exit_code
    }
    /// <p>The URL of the command log.</p>
    pub fn log_url(&self) -> ::std::option::Option<&str> {
        self.log_url.as_deref()
    }
    /// <p>The command type:</p>
    /// <ul>
    /// <li>
    /// <p><code>configure</code></p></li>
    /// <li>
    /// <p><code>deploy</code></p></li>
    /// <li>
    /// <p><code>execute_recipes</code></p></li>
    /// <li>
    /// <p><code>install_dependencies</code></p></li>
    /// <li>
    /// <p><code>restart</code></p></li>
    /// <li>
    /// <p><code>rollback</code></p></li>
    /// <li>
    /// <p><code>setup</code></p></li>
    /// <li>
    /// <p><code>start</code></p></li>
    /// <li>
    /// <p><code>stop</code></p></li>
    /// <li>
    /// <p><code>undeploy</code></p></li>
    /// <li>
    /// <p><code>update_custom_cookbooks</code></p></li>
    /// <li>
    /// <p><code>update_dependencies</code></p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
}
impl Command {
    /// Creates a new builder-style object to manufacture [`Command`](crate::types::Command).
    pub fn builder() -> crate::types::builders::CommandBuilder {
        crate::types::builders::CommandBuilder::default()
    }
}

/// A builder for [`Command`](crate::types::Command).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CommandBuilder {
    pub(crate) command_id: ::std::option::Option<::std::string::String>,
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) deployment_id: ::std::option::Option<::std::string::String>,
    pub(crate) created_at: ::std::option::Option<::std::string::String>,
    pub(crate) acknowledged_at: ::std::option::Option<::std::string::String>,
    pub(crate) completed_at: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<::std::string::String>,
    pub(crate) exit_code: ::std::option::Option<i32>,
    pub(crate) log_url: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
}
impl CommandBuilder {
    /// <p>The command ID.</p>
    pub fn command_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.command_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The command ID.</p>
    pub fn set_command_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.command_id = input;
        self
    }
    /// <p>The command ID.</p>
    pub fn get_command_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.command_id
    }
    /// <p>The ID of the instance where the command was executed.</p>
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the instance where the command was executed.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The ID of the instance where the command was executed.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The command deployment ID.</p>
    pub fn deployment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.deployment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The command deployment ID.</p>
    pub fn set_deployment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.deployment_id = input;
        self
    }
    /// <p>The command deployment ID.</p>
    pub fn get_deployment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.deployment_id
    }
    /// <p>Date and time when the command was run.</p>
    pub fn created_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.created_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Date and time when the command was run.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>Date and time when the command was run.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.created_at
    }
    /// <p>Date and time when the command was acknowledged.</p>
    pub fn acknowledged_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.acknowledged_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Date and time when the command was acknowledged.</p>
    pub fn set_acknowledged_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.acknowledged_at = input;
        self
    }
    /// <p>Date and time when the command was acknowledged.</p>
    pub fn get_acknowledged_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.acknowledged_at
    }
    /// <p>Date when the command completed.</p>
    pub fn completed_at(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.completed_at = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Date when the command completed.</p>
    pub fn set_completed_at(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.completed_at = input;
        self
    }
    /// <p>Date when the command completed.</p>
    pub fn get_completed_at(&self) -> &::std::option::Option<::std::string::String> {
        &self.completed_at
    }
    /// <p>The command status:</p>
    /// <ul>
    /// <li>
    /// <p>failed</p></li>
    /// <li>
    /// <p>successful</p></li>
    /// <li>
    /// <p>skipped</p></li>
    /// <li>
    /// <p>pending</p></li>
    /// </ul>
    pub fn status(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.status = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The command status:</p>
    /// <ul>
    /// <li>
    /// <p>failed</p></li>
    /// <li>
    /// <p>successful</p></li>
    /// <li>
    /// <p>skipped</p></li>
    /// <li>
    /// <p>pending</p></li>
    /// </ul>
    pub fn set_status(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.status = input;
        self
    }
    /// <p>The command status:</p>
    /// <ul>
    /// <li>
    /// <p>failed</p></li>
    /// <li>
    /// <p>successful</p></li>
    /// <li>
    /// <p>skipped</p></li>
    /// <li>
    /// <p>pending</p></li>
    /// </ul>
    pub fn get_status(&self) -> &::std::option::Option<::std::string::String> {
        &self.status
    }
    /// <p>The command exit code.</p>
    pub fn exit_code(mut self, input: i32) -> Self {
        self.exit_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The command exit code.</p>
    pub fn set_exit_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.exit_code = input;
        self
    }
    /// <p>The command exit code.</p>
    pub fn get_exit_code(&self) -> &::std::option::Option<i32> {
        &self.exit_code
    }
    /// <p>The URL of the command log.</p>
    pub fn log_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the command log.</p>
    pub fn set_log_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_url = input;
        self
    }
    /// <p>The URL of the command log.</p>
    pub fn get_log_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_url
    }
    /// <p>The command type:</p>
    /// <ul>
    /// <li>
    /// <p><code>configure</code></p></li>
    /// <li>
    /// <p><code>deploy</code></p></li>
    /// <li>
    /// <p><code>execute_recipes</code></p></li>
    /// <li>
    /// <p><code>install_dependencies</code></p></li>
    /// <li>
    /// <p><code>restart</code></p></li>
    /// <li>
    /// <p><code>rollback</code></p></li>
    /// <li>
    /// <p><code>setup</code></p></li>
    /// <li>
    /// <p><code>start</code></p></li>
    /// <li>
    /// <p><code>stop</code></p></li>
    /// <li>
    /// <p><code>undeploy</code></p></li>
    /// <li>
    /// <p><code>update_custom_cookbooks</code></p></li>
    /// <li>
    /// <p><code>update_dependencies</code></p></li>
    /// </ul>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The command type:</p>
    /// <ul>
    /// <li>
    /// <p><code>configure</code></p></li>
    /// <li>
    /// <p><code>deploy</code></p></li>
    /// <li>
    /// <p><code>execute_recipes</code></p></li>
    /// <li>
    /// <p><code>install_dependencies</code></p></li>
    /// <li>
    /// <p><code>restart</code></p></li>
    /// <li>
    /// <p><code>rollback</code></p></li>
    /// <li>
    /// <p><code>setup</code></p></li>
    /// <li>
    /// <p><code>start</code></p></li>
    /// <li>
    /// <p><code>stop</code></p></li>
    /// <li>
    /// <p><code>undeploy</code></p></li>
    /// <li>
    /// <p><code>update_custom_cookbooks</code></p></li>
    /// <li>
    /// <p><code>update_dependencies</code></p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The command type:</p>
    /// <ul>
    /// <li>
    /// <p><code>configure</code></p></li>
    /// <li>
    /// <p><code>deploy</code></p></li>
    /// <li>
    /// <p><code>execute_recipes</code></p></li>
    /// <li>
    /// <p><code>install_dependencies</code></p></li>
    /// <li>
    /// <p><code>restart</code></p></li>
    /// <li>
    /// <p><code>rollback</code></p></li>
    /// <li>
    /// <p><code>setup</code></p></li>
    /// <li>
    /// <p><code>start</code></p></li>
    /// <li>
    /// <p><code>stop</code></p></li>
    /// <li>
    /// <p><code>undeploy</code></p></li>
    /// <li>
    /// <p><code>update_custom_cookbooks</code></p></li>
    /// <li>
    /// <p><code>update_dependencies</code></p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`Command`](crate::types::Command).
    pub fn build(self) -> crate::types::Command {
        crate::types::Command {
            command_id: self.command_id,
            instance_id: self.instance_id,
            deployment_id: self.deployment_id,
            created_at: self.created_at,
            acknowledged_at: self.acknowledged_at,
            completed_at: self.completed_at,
            status: self.status,
            exit_code: self.exit_code,
            log_url: self.log_url,
            r#type: self.r#type,
        }
    }
}
