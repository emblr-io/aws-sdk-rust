// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct UpdateStateMachineInput {
    /// <p>The Amazon Resource Name (ARN) of the state machine.</p>
    pub state_machine_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon States Language definition of the state machine. See <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-amazon-states-language.html">Amazon States Language</a>.</p>
    pub definition: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the IAM role of the state machine.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>Use the <code>LoggingConfiguration</code> data type to set CloudWatch Logs options.</p>
    pub logging_configuration: ::std::option::Option<crate::types::LoggingConfiguration>,
    /// <p>Selects whether X-Ray tracing is enabled.</p>
    pub tracing_configuration: ::std::option::Option<crate::types::TracingConfiguration>,
    /// <p>Specifies whether the state machine version is published. The default is <code>false</code>. To publish a version after updating the state machine, set <code>publish</code> to <code>true</code>.</p>
    pub publish: ::std::option::Option<bool>,
    /// <p>An optional description of the state machine version to publish.</p>
    /// <p>You can only specify the <code>versionDescription</code> parameter if you've set <code>publish</code> to <code>true</code>.</p>
    pub version_description: ::std::option::Option<::std::string::String>,
    /// <p>Settings to configure server-side encryption.</p>
    pub encryption_configuration: ::std::option::Option<crate::types::EncryptionConfiguration>,
}
impl UpdateStateMachineInput {
    /// <p>The Amazon Resource Name (ARN) of the state machine.</p>
    pub fn state_machine_arn(&self) -> ::std::option::Option<&str> {
        self.state_machine_arn.as_deref()
    }
    /// <p>The Amazon States Language definition of the state machine. See <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-amazon-states-language.html">Amazon States Language</a>.</p>
    pub fn definition(&self) -> ::std::option::Option<&str> {
        self.definition.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role of the state machine.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>Use the <code>LoggingConfiguration</code> data type to set CloudWatch Logs options.</p>
    pub fn logging_configuration(&self) -> ::std::option::Option<&crate::types::LoggingConfiguration> {
        self.logging_configuration.as_ref()
    }
    /// <p>Selects whether X-Ray tracing is enabled.</p>
    pub fn tracing_configuration(&self) -> ::std::option::Option<&crate::types::TracingConfiguration> {
        self.tracing_configuration.as_ref()
    }
    /// <p>Specifies whether the state machine version is published. The default is <code>false</code>. To publish a version after updating the state machine, set <code>publish</code> to <code>true</code>.</p>
    pub fn publish(&self) -> ::std::option::Option<bool> {
        self.publish
    }
    /// <p>An optional description of the state machine version to publish.</p>
    /// <p>You can only specify the <code>versionDescription</code> parameter if you've set <code>publish</code> to <code>true</code>.</p>
    pub fn version_description(&self) -> ::std::option::Option<&str> {
        self.version_description.as_deref()
    }
    /// <p>Settings to configure server-side encryption.</p>
    pub fn encryption_configuration(&self) -> ::std::option::Option<&crate::types::EncryptionConfiguration> {
        self.encryption_configuration.as_ref()
    }
}
impl ::std::fmt::Debug for UpdateStateMachineInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateStateMachineInput");
        formatter.field("state_machine_arn", &self.state_machine_arn);
        formatter.field("definition", &"*** Sensitive Data Redacted ***");
        formatter.field("role_arn", &self.role_arn);
        formatter.field("logging_configuration", &self.logging_configuration);
        formatter.field("tracing_configuration", &self.tracing_configuration);
        formatter.field("publish", &self.publish);
        formatter.field("version_description", &"*** Sensitive Data Redacted ***");
        formatter.field("encryption_configuration", &self.encryption_configuration);
        formatter.finish()
    }
}
impl UpdateStateMachineInput {
    /// Creates a new builder-style object to manufacture [`UpdateStateMachineInput`](crate::operation::update_state_machine::UpdateStateMachineInput).
    pub fn builder() -> crate::operation::update_state_machine::builders::UpdateStateMachineInputBuilder {
        crate::operation::update_state_machine::builders::UpdateStateMachineInputBuilder::default()
    }
}

/// A builder for [`UpdateStateMachineInput`](crate::operation::update_state_machine::UpdateStateMachineInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct UpdateStateMachineInputBuilder {
    pub(crate) state_machine_arn: ::std::option::Option<::std::string::String>,
    pub(crate) definition: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) logging_configuration: ::std::option::Option<crate::types::LoggingConfiguration>,
    pub(crate) tracing_configuration: ::std::option::Option<crate::types::TracingConfiguration>,
    pub(crate) publish: ::std::option::Option<bool>,
    pub(crate) version_description: ::std::option::Option<::std::string::String>,
    pub(crate) encryption_configuration: ::std::option::Option<crate::types::EncryptionConfiguration>,
}
impl UpdateStateMachineInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the state machine.</p>
    /// This field is required.
    pub fn state_machine_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.state_machine_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the state machine.</p>
    pub fn set_state_machine_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.state_machine_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the state machine.</p>
    pub fn get_state_machine_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.state_machine_arn
    }
    /// <p>The Amazon States Language definition of the state machine. See <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-amazon-states-language.html">Amazon States Language</a>.</p>
    pub fn definition(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.definition = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon States Language definition of the state machine. See <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-amazon-states-language.html">Amazon States Language</a>.</p>
    pub fn set_definition(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.definition = input;
        self
    }
    /// <p>The Amazon States Language definition of the state machine. See <a href="https://docs.aws.amazon.com/step-functions/latest/dg/concepts-amazon-states-language.html">Amazon States Language</a>.</p>
    pub fn get_definition(&self) -> &::std::option::Option<::std::string::String> {
        &self.definition
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role of the state machine.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role of the state machine.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM role of the state machine.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>Use the <code>LoggingConfiguration</code> data type to set CloudWatch Logs options.</p>
    pub fn logging_configuration(mut self, input: crate::types::LoggingConfiguration) -> Self {
        self.logging_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Use the <code>LoggingConfiguration</code> data type to set CloudWatch Logs options.</p>
    pub fn set_logging_configuration(mut self, input: ::std::option::Option<crate::types::LoggingConfiguration>) -> Self {
        self.logging_configuration = input;
        self
    }
    /// <p>Use the <code>LoggingConfiguration</code> data type to set CloudWatch Logs options.</p>
    pub fn get_logging_configuration(&self) -> &::std::option::Option<crate::types::LoggingConfiguration> {
        &self.logging_configuration
    }
    /// <p>Selects whether X-Ray tracing is enabled.</p>
    pub fn tracing_configuration(mut self, input: crate::types::TracingConfiguration) -> Self {
        self.tracing_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Selects whether X-Ray tracing is enabled.</p>
    pub fn set_tracing_configuration(mut self, input: ::std::option::Option<crate::types::TracingConfiguration>) -> Self {
        self.tracing_configuration = input;
        self
    }
    /// <p>Selects whether X-Ray tracing is enabled.</p>
    pub fn get_tracing_configuration(&self) -> &::std::option::Option<crate::types::TracingConfiguration> {
        &self.tracing_configuration
    }
    /// <p>Specifies whether the state machine version is published. The default is <code>false</code>. To publish a version after updating the state machine, set <code>publish</code> to <code>true</code>.</p>
    pub fn publish(mut self, input: bool) -> Self {
        self.publish = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies whether the state machine version is published. The default is <code>false</code>. To publish a version after updating the state machine, set <code>publish</code> to <code>true</code>.</p>
    pub fn set_publish(mut self, input: ::std::option::Option<bool>) -> Self {
        self.publish = input;
        self
    }
    /// <p>Specifies whether the state machine version is published. The default is <code>false</code>. To publish a version after updating the state machine, set <code>publish</code> to <code>true</code>.</p>
    pub fn get_publish(&self) -> &::std::option::Option<bool> {
        &self.publish
    }
    /// <p>An optional description of the state machine version to publish.</p>
    /// <p>You can only specify the <code>versionDescription</code> parameter if you've set <code>publish</code> to <code>true</code>.</p>
    pub fn version_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional description of the state machine version to publish.</p>
    /// <p>You can only specify the <code>versionDescription</code> parameter if you've set <code>publish</code> to <code>true</code>.</p>
    pub fn set_version_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version_description = input;
        self
    }
    /// <p>An optional description of the state machine version to publish.</p>
    /// <p>You can only specify the <code>versionDescription</code> parameter if you've set <code>publish</code> to <code>true</code>.</p>
    pub fn get_version_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.version_description
    }
    /// <p>Settings to configure server-side encryption.</p>
    pub fn encryption_configuration(mut self, input: crate::types::EncryptionConfiguration) -> Self {
        self.encryption_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings to configure server-side encryption.</p>
    pub fn set_encryption_configuration(mut self, input: ::std::option::Option<crate::types::EncryptionConfiguration>) -> Self {
        self.encryption_configuration = input;
        self
    }
    /// <p>Settings to configure server-side encryption.</p>
    pub fn get_encryption_configuration(&self) -> &::std::option::Option<crate::types::EncryptionConfiguration> {
        &self.encryption_configuration
    }
    /// Consumes the builder and constructs a [`UpdateStateMachineInput`](crate::operation::update_state_machine::UpdateStateMachineInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_state_machine::UpdateStateMachineInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_state_machine::UpdateStateMachineInput {
            state_machine_arn: self.state_machine_arn,
            definition: self.definition,
            role_arn: self.role_arn,
            logging_configuration: self.logging_configuration,
            tracing_configuration: self.tracing_configuration,
            publish: self.publish,
            version_description: self.version_description,
            encryption_configuration: self.encryption_configuration,
        })
    }
}
impl ::std::fmt::Debug for UpdateStateMachineInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("UpdateStateMachineInputBuilder");
        formatter.field("state_machine_arn", &self.state_machine_arn);
        formatter.field("definition", &"*** Sensitive Data Redacted ***");
        formatter.field("role_arn", &self.role_arn);
        formatter.field("logging_configuration", &self.logging_configuration);
        formatter.field("tracing_configuration", &self.tracing_configuration);
        formatter.field("publish", &self.publish);
        formatter.field("version_description", &"*** Sensitive Data Redacted ***");
        formatter.field("encryption_configuration", &self.encryption_configuration);
        formatter.finish()
    }
}
