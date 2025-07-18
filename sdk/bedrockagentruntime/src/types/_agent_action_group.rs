// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details of the inline agent's action group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AgentActionGroup {
    /// <p>The name of the action group.</p>
    pub action_group_name: ::std::string::String,
    /// <p>A description of the action group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Specify a built-in or computer use action for this action group. If you specify a value, you must leave the <code>description</code>, <code>apiSchema</code>, and <code>actionGroupExecutor</code> fields empty for this action group.</p>
    /// <ul>
    /// <li>
    /// <p>To allow your agent to request the user for additional information when trying to complete a task, set this field to <code>AMAZON.UserInput</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to generate, run, and troubleshoot code when trying to complete a task, set this field to <code>AMAZON.CodeInterpreter</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to use an Anthropic computer use tool, specify one of the following values.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Anthropic Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. When operating computer use functionality, we recommend taking additional security precautions, such as executing computer actions in virtual environments with restricted data access and limited internet connectivity. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>ANTHROPIC.Computer</code> - Gives the agent permission to use the mouse and keyboard and take screenshots.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.TextEditor</code> - Gives the agent permission to view, create and edit files.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.Bash</code> - Gives the agent permission to run commands in a bash shell.</p></li>
    /// </ul></li>
    /// </ul>
    pub parent_action_group_signature: ::std::option::Option<crate::types::ActionGroupSignature>,
    /// <p>The Amazon Resource Name (ARN) of the Lambda function containing the business logic that is carried out upon invoking the action or the custom control method for handling the information elicited from the user.</p>
    pub action_group_executor: ::std::option::Option<crate::types::ActionGroupExecutor>,
    /// <p>Contains either details about the S3 object containing the OpenAPI schema for the action group or the JSON or YAML-formatted payload defining the schema. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-api-schema.html">Action group OpenAPI schemas</a>.</p>
    pub api_schema: ::std::option::Option<crate::types::ApiSchema>,
    /// <p>Contains details about the function schema for the action group or the JSON or YAML-formatted payload defining the schema.</p>
    pub function_schema: ::std::option::Option<crate::types::FunctionSchema>,
    /// <p>The configuration settings for a computer use action.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    pub parent_action_group_signature_params: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl AgentActionGroup {
    /// <p>The name of the action group.</p>
    pub fn action_group_name(&self) -> &str {
        use std::ops::Deref;
        self.action_group_name.deref()
    }
    /// <p>A description of the action group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Specify a built-in or computer use action for this action group. If you specify a value, you must leave the <code>description</code>, <code>apiSchema</code>, and <code>actionGroupExecutor</code> fields empty for this action group.</p>
    /// <ul>
    /// <li>
    /// <p>To allow your agent to request the user for additional information when trying to complete a task, set this field to <code>AMAZON.UserInput</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to generate, run, and troubleshoot code when trying to complete a task, set this field to <code>AMAZON.CodeInterpreter</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to use an Anthropic computer use tool, specify one of the following values.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Anthropic Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. When operating computer use functionality, we recommend taking additional security precautions, such as executing computer actions in virtual environments with restricted data access and limited internet connectivity. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>ANTHROPIC.Computer</code> - Gives the agent permission to use the mouse and keyboard and take screenshots.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.TextEditor</code> - Gives the agent permission to view, create and edit files.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.Bash</code> - Gives the agent permission to run commands in a bash shell.</p></li>
    /// </ul></li>
    /// </ul>
    pub fn parent_action_group_signature(&self) -> ::std::option::Option<&crate::types::ActionGroupSignature> {
        self.parent_action_group_signature.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Lambda function containing the business logic that is carried out upon invoking the action or the custom control method for handling the information elicited from the user.</p>
    pub fn action_group_executor(&self) -> ::std::option::Option<&crate::types::ActionGroupExecutor> {
        self.action_group_executor.as_ref()
    }
    /// <p>Contains either details about the S3 object containing the OpenAPI schema for the action group or the JSON or YAML-formatted payload defining the schema. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-api-schema.html">Action group OpenAPI schemas</a>.</p>
    pub fn api_schema(&self) -> ::std::option::Option<&crate::types::ApiSchema> {
        self.api_schema.as_ref()
    }
    /// <p>Contains details about the function schema for the action group or the JSON or YAML-formatted payload defining the schema.</p>
    pub fn function_schema(&self) -> ::std::option::Option<&crate::types::FunctionSchema> {
        self.function_schema.as_ref()
    }
    /// <p>The configuration settings for a computer use action.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    pub fn parent_action_group_signature_params(
        &self,
    ) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.parent_action_group_signature_params.as_ref()
    }
}
impl ::std::fmt::Debug for AgentActionGroup {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AgentActionGroup");
        formatter.field("action_group_name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("parent_action_group_signature", &self.parent_action_group_signature);
        formatter.field("action_group_executor", &self.action_group_executor);
        formatter.field("api_schema", &self.api_schema);
        formatter.field("function_schema", &self.function_schema);
        formatter.field("parent_action_group_signature_params", &self.parent_action_group_signature_params);
        formatter.finish()
    }
}
impl AgentActionGroup {
    /// Creates a new builder-style object to manufacture [`AgentActionGroup`](crate::types::AgentActionGroup).
    pub fn builder() -> crate::types::builders::AgentActionGroupBuilder {
        crate::types::builders::AgentActionGroupBuilder::default()
    }
}

/// A builder for [`AgentActionGroup`](crate::types::AgentActionGroup).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AgentActionGroupBuilder {
    pub(crate) action_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) parent_action_group_signature: ::std::option::Option<crate::types::ActionGroupSignature>,
    pub(crate) action_group_executor: ::std::option::Option<crate::types::ActionGroupExecutor>,
    pub(crate) api_schema: ::std::option::Option<crate::types::ApiSchema>,
    pub(crate) function_schema: ::std::option::Option<crate::types::FunctionSchema>,
    pub(crate) parent_action_group_signature_params: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl AgentActionGroupBuilder {
    /// <p>The name of the action group.</p>
    /// This field is required.
    pub fn action_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the action group.</p>
    pub fn set_action_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_group_name = input;
        self
    }
    /// <p>The name of the action group.</p>
    pub fn get_action_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_group_name
    }
    /// <p>A description of the action group.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the action group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the action group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Specify a built-in or computer use action for this action group. If you specify a value, you must leave the <code>description</code>, <code>apiSchema</code>, and <code>actionGroupExecutor</code> fields empty for this action group.</p>
    /// <ul>
    /// <li>
    /// <p>To allow your agent to request the user for additional information when trying to complete a task, set this field to <code>AMAZON.UserInput</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to generate, run, and troubleshoot code when trying to complete a task, set this field to <code>AMAZON.CodeInterpreter</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to use an Anthropic computer use tool, specify one of the following values.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Anthropic Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. When operating computer use functionality, we recommend taking additional security precautions, such as executing computer actions in virtual environments with restricted data access and limited internet connectivity. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>ANTHROPIC.Computer</code> - Gives the agent permission to use the mouse and keyboard and take screenshots.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.TextEditor</code> - Gives the agent permission to view, create and edit files.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.Bash</code> - Gives the agent permission to run commands in a bash shell.</p></li>
    /// </ul></li>
    /// </ul>
    pub fn parent_action_group_signature(mut self, input: crate::types::ActionGroupSignature) -> Self {
        self.parent_action_group_signature = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specify a built-in or computer use action for this action group. If you specify a value, you must leave the <code>description</code>, <code>apiSchema</code>, and <code>actionGroupExecutor</code> fields empty for this action group.</p>
    /// <ul>
    /// <li>
    /// <p>To allow your agent to request the user for additional information when trying to complete a task, set this field to <code>AMAZON.UserInput</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to generate, run, and troubleshoot code when trying to complete a task, set this field to <code>AMAZON.CodeInterpreter</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to use an Anthropic computer use tool, specify one of the following values.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Anthropic Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. When operating computer use functionality, we recommend taking additional security precautions, such as executing computer actions in virtual environments with restricted data access and limited internet connectivity. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>ANTHROPIC.Computer</code> - Gives the agent permission to use the mouse and keyboard and take screenshots.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.TextEditor</code> - Gives the agent permission to view, create and edit files.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.Bash</code> - Gives the agent permission to run commands in a bash shell.</p></li>
    /// </ul></li>
    /// </ul>
    pub fn set_parent_action_group_signature(mut self, input: ::std::option::Option<crate::types::ActionGroupSignature>) -> Self {
        self.parent_action_group_signature = input;
        self
    }
    /// <p>Specify a built-in or computer use action for this action group. If you specify a value, you must leave the <code>description</code>, <code>apiSchema</code>, and <code>actionGroupExecutor</code> fields empty for this action group.</p>
    /// <ul>
    /// <li>
    /// <p>To allow your agent to request the user for additional information when trying to complete a task, set this field to <code>AMAZON.UserInput</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to generate, run, and troubleshoot code when trying to complete a task, set this field to <code>AMAZON.CodeInterpreter</code>.</p></li>
    /// <li>
    /// <p>To allow your agent to use an Anthropic computer use tool, specify one of the following values.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Anthropic Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. When operating computer use functionality, we recommend taking additional security precautions, such as executing computer actions in virtual environments with restricted data access and limited internet connectivity. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    /// <ul>
    /// <li>
    /// <p><code>ANTHROPIC.Computer</code> - Gives the agent permission to use the mouse and keyboard and take screenshots.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.TextEditor</code> - Gives the agent permission to view, create and edit files.</p></li>
    /// <li>
    /// <p><code>ANTHROPIC.Bash</code> - Gives the agent permission to run commands in a bash shell.</p></li>
    /// </ul></li>
    /// </ul>
    pub fn get_parent_action_group_signature(&self) -> &::std::option::Option<crate::types::ActionGroupSignature> {
        &self.parent_action_group_signature
    }
    /// <p>The Amazon Resource Name (ARN) of the Lambda function containing the business logic that is carried out upon invoking the action or the custom control method for handling the information elicited from the user.</p>
    pub fn action_group_executor(mut self, input: crate::types::ActionGroupExecutor) -> Self {
        self.action_group_executor = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Lambda function containing the business logic that is carried out upon invoking the action or the custom control method for handling the information elicited from the user.</p>
    pub fn set_action_group_executor(mut self, input: ::std::option::Option<crate::types::ActionGroupExecutor>) -> Self {
        self.action_group_executor = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Lambda function containing the business logic that is carried out upon invoking the action or the custom control method for handling the information elicited from the user.</p>
    pub fn get_action_group_executor(&self) -> &::std::option::Option<crate::types::ActionGroupExecutor> {
        &self.action_group_executor
    }
    /// <p>Contains either details about the S3 object containing the OpenAPI schema for the action group or the JSON or YAML-formatted payload defining the schema. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-api-schema.html">Action group OpenAPI schemas</a>.</p>
    pub fn api_schema(mut self, input: crate::types::ApiSchema) -> Self {
        self.api_schema = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains either details about the S3 object containing the OpenAPI schema for the action group or the JSON or YAML-formatted payload defining the schema. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-api-schema.html">Action group OpenAPI schemas</a>.</p>
    pub fn set_api_schema(mut self, input: ::std::option::Option<crate::types::ApiSchema>) -> Self {
        self.api_schema = input;
        self
    }
    /// <p>Contains either details about the S3 object containing the OpenAPI schema for the action group or the JSON or YAML-formatted payload defining the schema. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agents-api-schema.html">Action group OpenAPI schemas</a>.</p>
    pub fn get_api_schema(&self) -> &::std::option::Option<crate::types::ApiSchema> {
        &self.api_schema
    }
    /// <p>Contains details about the function schema for the action group or the JSON or YAML-formatted payload defining the schema.</p>
    pub fn function_schema(mut self, input: crate::types::FunctionSchema) -> Self {
        self.function_schema = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains details about the function schema for the action group or the JSON or YAML-formatted payload defining the schema.</p>
    pub fn set_function_schema(mut self, input: ::std::option::Option<crate::types::FunctionSchema>) -> Self {
        self.function_schema = input;
        self
    }
    /// <p>Contains details about the function schema for the action group or the JSON or YAML-formatted payload defining the schema.</p>
    pub fn get_function_schema(&self) -> &::std::option::Option<crate::types::FunctionSchema> {
        &self.function_schema
    }
    /// Adds a key-value pair to `parent_action_group_signature_params`.
    ///
    /// To override the contents of this collection use [`set_parent_action_group_signature_params`](Self::set_parent_action_group_signature_params).
    ///
    /// <p>The configuration settings for a computer use action.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    pub fn parent_action_group_signature_params(
        mut self,
        k: impl ::std::convert::Into<::std::string::String>,
        v: impl ::std::convert::Into<::std::string::String>,
    ) -> Self {
        let mut hash_map = self.parent_action_group_signature_params.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.parent_action_group_signature_params = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The configuration settings for a computer use action.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    pub fn set_parent_action_group_signature_params(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
    ) -> Self {
        self.parent_action_group_signature_params = input;
        self
    }
    /// <p>The configuration settings for a computer use action.</p><important>
    /// <p>Computer use is a new Anthropic Claude model capability (in beta) available with Claude 3.7 Sonnet and Claude 3.5 Sonnet v2 only. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/agent-computer-use.html">Configure an Amazon Bedrock Agent to complete tasks with computer use tools</a>.</p>
    /// </important>
    pub fn get_parent_action_group_signature_params(
        &self,
    ) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.parent_action_group_signature_params
    }
    /// Consumes the builder and constructs a [`AgentActionGroup`](crate::types::AgentActionGroup).
    /// This method will fail if any of the following fields are not set:
    /// - [`action_group_name`](crate::types::builders::AgentActionGroupBuilder::action_group_name)
    pub fn build(self) -> ::std::result::Result<crate::types::AgentActionGroup, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AgentActionGroup {
            action_group_name: self.action_group_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "action_group_name",
                    "action_group_name was not specified but it is required when building AgentActionGroup",
                )
            })?,
            description: self.description,
            parent_action_group_signature: self.parent_action_group_signature,
            action_group_executor: self.action_group_executor,
            api_schema: self.api_schema,
            function_schema: self.function_schema,
            parent_action_group_signature_params: self.parent_action_group_signature_params,
        })
    }
}
impl ::std::fmt::Debug for AgentActionGroupBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AgentActionGroupBuilder");
        formatter.field("action_group_name", &"*** Sensitive Data Redacted ***");
        formatter.field("description", &"*** Sensitive Data Redacted ***");
        formatter.field("parent_action_group_signature", &self.parent_action_group_signature);
        formatter.field("action_group_executor", &self.action_group_executor);
        formatter.field("api_schema", &self.api_schema);
        formatter.field("function_schema", &self.function_schema);
        formatter.field("parent_action_group_signature_params", &self.parent_action_group_signature_params);
        formatter.finish()
    }
}
