// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the execute command configuration.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecuteCommandConfiguration {
    /// <p>Specify an Key Management Service key ID to encrypt the data between the local client and the container.</p>
    pub kms_key_id: ::std::option::Option<::std::string::String>,
    /// <p>The log setting to use for redirecting logs for your execute command results. The following log settings are available.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The execute command session is not logged.</p></li>
    /// <li>
    /// <p><code>DEFAULT</code>: The <code>awslogs</code> configuration in the task definition is used. If no logging parameter is specified, it defaults to this value. If no <code>awslogs</code> log driver is configured in the task definition, the output won't be logged.</p></li>
    /// <li>
    /// <p><code>OVERRIDE</code>: Specify the logging details as a part of <code>logConfiguration</code>. If the <code>OVERRIDE</code> logging option is specified, the <code>logConfiguration</code> is required.</p></li>
    /// </ul>
    pub logging: ::std::option::Option<crate::types::ExecuteCommandLogging>,
    /// <p>The log configuration for the results of the execute command actions. The logs can be sent to CloudWatch Logs or an Amazon S3 bucket. When <code>logging=OVERRIDE</code> is specified, a <code>logConfiguration</code> must be provided.</p>
    pub log_configuration: ::std::option::Option<crate::types::ExecuteCommandLogConfiguration>,
}
impl ExecuteCommandConfiguration {
    /// <p>Specify an Key Management Service key ID to encrypt the data between the local client and the container.</p>
    pub fn kms_key_id(&self) -> ::std::option::Option<&str> {
        self.kms_key_id.as_deref()
    }
    /// <p>The log setting to use for redirecting logs for your execute command results. The following log settings are available.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The execute command session is not logged.</p></li>
    /// <li>
    /// <p><code>DEFAULT</code>: The <code>awslogs</code> configuration in the task definition is used. If no logging parameter is specified, it defaults to this value. If no <code>awslogs</code> log driver is configured in the task definition, the output won't be logged.</p></li>
    /// <li>
    /// <p><code>OVERRIDE</code>: Specify the logging details as a part of <code>logConfiguration</code>. If the <code>OVERRIDE</code> logging option is specified, the <code>logConfiguration</code> is required.</p></li>
    /// </ul>
    pub fn logging(&self) -> ::std::option::Option<&crate::types::ExecuteCommandLogging> {
        self.logging.as_ref()
    }
    /// <p>The log configuration for the results of the execute command actions. The logs can be sent to CloudWatch Logs or an Amazon S3 bucket. When <code>logging=OVERRIDE</code> is specified, a <code>logConfiguration</code> must be provided.</p>
    pub fn log_configuration(&self) -> ::std::option::Option<&crate::types::ExecuteCommandLogConfiguration> {
        self.log_configuration.as_ref()
    }
}
impl ExecuteCommandConfiguration {
    /// Creates a new builder-style object to manufacture [`ExecuteCommandConfiguration`](crate::types::ExecuteCommandConfiguration).
    pub fn builder() -> crate::types::builders::ExecuteCommandConfigurationBuilder {
        crate::types::builders::ExecuteCommandConfigurationBuilder::default()
    }
}

/// A builder for [`ExecuteCommandConfiguration`](crate::types::ExecuteCommandConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecuteCommandConfigurationBuilder {
    pub(crate) kms_key_id: ::std::option::Option<::std::string::String>,
    pub(crate) logging: ::std::option::Option<crate::types::ExecuteCommandLogging>,
    pub(crate) log_configuration: ::std::option::Option<crate::types::ExecuteCommandLogConfiguration>,
}
impl ExecuteCommandConfigurationBuilder {
    /// <p>Specify an Key Management Service key ID to encrypt the data between the local client and the container.</p>
    pub fn kms_key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.kms_key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specify an Key Management Service key ID to encrypt the data between the local client and the container.</p>
    pub fn set_kms_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.kms_key_id = input;
        self
    }
    /// <p>Specify an Key Management Service key ID to encrypt the data between the local client and the container.</p>
    pub fn get_kms_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.kms_key_id
    }
    /// <p>The log setting to use for redirecting logs for your execute command results. The following log settings are available.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The execute command session is not logged.</p></li>
    /// <li>
    /// <p><code>DEFAULT</code>: The <code>awslogs</code> configuration in the task definition is used. If no logging parameter is specified, it defaults to this value. If no <code>awslogs</code> log driver is configured in the task definition, the output won't be logged.</p></li>
    /// <li>
    /// <p><code>OVERRIDE</code>: Specify the logging details as a part of <code>logConfiguration</code>. If the <code>OVERRIDE</code> logging option is specified, the <code>logConfiguration</code> is required.</p></li>
    /// </ul>
    pub fn logging(mut self, input: crate::types::ExecuteCommandLogging) -> Self {
        self.logging = ::std::option::Option::Some(input);
        self
    }
    /// <p>The log setting to use for redirecting logs for your execute command results. The following log settings are available.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The execute command session is not logged.</p></li>
    /// <li>
    /// <p><code>DEFAULT</code>: The <code>awslogs</code> configuration in the task definition is used. If no logging parameter is specified, it defaults to this value. If no <code>awslogs</code> log driver is configured in the task definition, the output won't be logged.</p></li>
    /// <li>
    /// <p><code>OVERRIDE</code>: Specify the logging details as a part of <code>logConfiguration</code>. If the <code>OVERRIDE</code> logging option is specified, the <code>logConfiguration</code> is required.</p></li>
    /// </ul>
    pub fn set_logging(mut self, input: ::std::option::Option<crate::types::ExecuteCommandLogging>) -> Self {
        self.logging = input;
        self
    }
    /// <p>The log setting to use for redirecting logs for your execute command results. The following log settings are available.</p>
    /// <ul>
    /// <li>
    /// <p><code>NONE</code>: The execute command session is not logged.</p></li>
    /// <li>
    /// <p><code>DEFAULT</code>: The <code>awslogs</code> configuration in the task definition is used. If no logging parameter is specified, it defaults to this value. If no <code>awslogs</code> log driver is configured in the task definition, the output won't be logged.</p></li>
    /// <li>
    /// <p><code>OVERRIDE</code>: Specify the logging details as a part of <code>logConfiguration</code>. If the <code>OVERRIDE</code> logging option is specified, the <code>logConfiguration</code> is required.</p></li>
    /// </ul>
    pub fn get_logging(&self) -> &::std::option::Option<crate::types::ExecuteCommandLogging> {
        &self.logging
    }
    /// <p>The log configuration for the results of the execute command actions. The logs can be sent to CloudWatch Logs or an Amazon S3 bucket. When <code>logging=OVERRIDE</code> is specified, a <code>logConfiguration</code> must be provided.</p>
    pub fn log_configuration(mut self, input: crate::types::ExecuteCommandLogConfiguration) -> Self {
        self.log_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>The log configuration for the results of the execute command actions. The logs can be sent to CloudWatch Logs or an Amazon S3 bucket. When <code>logging=OVERRIDE</code> is specified, a <code>logConfiguration</code> must be provided.</p>
    pub fn set_log_configuration(mut self, input: ::std::option::Option<crate::types::ExecuteCommandLogConfiguration>) -> Self {
        self.log_configuration = input;
        self
    }
    /// <p>The log configuration for the results of the execute command actions. The logs can be sent to CloudWatch Logs or an Amazon S3 bucket. When <code>logging=OVERRIDE</code> is specified, a <code>logConfiguration</code> must be provided.</p>
    pub fn get_log_configuration(&self) -> &::std::option::Option<crate::types::ExecuteCommandLogConfiguration> {
        &self.log_configuration
    }
    /// Consumes the builder and constructs a [`ExecuteCommandConfiguration`](crate::types::ExecuteCommandConfiguration).
    pub fn build(self) -> crate::types::ExecuteCommandConfiguration {
        crate::types::ExecuteCommandConfiguration {
            kms_key_id: self.kms_key_id,
            logging: self.logging,
            log_configuration: self.log_configuration,
        }
    }
}
