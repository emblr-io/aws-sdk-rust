// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the current state of a container service.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ContainerServiceStateDetail {
    /// <p>The state code of the container service.</p>
    /// <p>The following state codes are possible:</p>
    /// <ul>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>DEPLOYING</code> or <code>UPDATING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING_SYSTEM_RESOURCES</code> - The system resources for your container service are being created.</p></li>
    /// <li>
    /// <p><code>CREATING_NETWORK_INFRASTRUCTURE</code> - The network infrastructure for your container service are being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_CERTIFICATE</code> - The SSL/TLS certificate for your container service is being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_SERVICE</code> - Your container service is being provisioned.</p></li>
    /// <li>
    /// <p><code>CREATING_DEPLOYMENT</code> - Your deployment is being created on your container service.</p></li>
    /// <li>
    /// <p><code>EVALUATING_HEALTH_CHECK</code> - The health of your deployment is being evaluated.</p></li>
    /// <li>
    /// <p><code>ACTIVATING_DEPLOYMENT</code> - Your deployment is being activated.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>PENDING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CERTIFICATE_LIMIT_EXCEEDED</code> - The SSL/TLS certificate required for your container service exceeds the maximum number of certificates allowed for your account.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code> - An error was experienced when your container service was being created.</p></li>
    /// </ul></li>
    /// </ul>
    pub code: ::std::option::Option<crate::types::ContainerServiceStateDetailCode>,
    /// <p>A message that provides more information for the state code.</p><note>
    /// <p>The state detail is populated only when a container service is in a <code>PENDING</code>, <code>DEPLOYING</code>, or <code>UPDATING</code> state.</p>
    /// </note>
    pub message: ::std::option::Option<::std::string::String>,
}
impl ContainerServiceStateDetail {
    /// <p>The state code of the container service.</p>
    /// <p>The following state codes are possible:</p>
    /// <ul>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>DEPLOYING</code> or <code>UPDATING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING_SYSTEM_RESOURCES</code> - The system resources for your container service are being created.</p></li>
    /// <li>
    /// <p><code>CREATING_NETWORK_INFRASTRUCTURE</code> - The network infrastructure for your container service are being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_CERTIFICATE</code> - The SSL/TLS certificate for your container service is being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_SERVICE</code> - Your container service is being provisioned.</p></li>
    /// <li>
    /// <p><code>CREATING_DEPLOYMENT</code> - Your deployment is being created on your container service.</p></li>
    /// <li>
    /// <p><code>EVALUATING_HEALTH_CHECK</code> - The health of your deployment is being evaluated.</p></li>
    /// <li>
    /// <p><code>ACTIVATING_DEPLOYMENT</code> - Your deployment is being activated.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>PENDING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CERTIFICATE_LIMIT_EXCEEDED</code> - The SSL/TLS certificate required for your container service exceeds the maximum number of certificates allowed for your account.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code> - An error was experienced when your container service was being created.</p></li>
    /// </ul></li>
    /// </ul>
    pub fn code(&self) -> ::std::option::Option<&crate::types::ContainerServiceStateDetailCode> {
        self.code.as_ref()
    }
    /// <p>A message that provides more information for the state code.</p><note>
    /// <p>The state detail is populated only when a container service is in a <code>PENDING</code>, <code>DEPLOYING</code>, or <code>UPDATING</code> state.</p>
    /// </note>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl ContainerServiceStateDetail {
    /// Creates a new builder-style object to manufacture [`ContainerServiceStateDetail`](crate::types::ContainerServiceStateDetail).
    pub fn builder() -> crate::types::builders::ContainerServiceStateDetailBuilder {
        crate::types::builders::ContainerServiceStateDetailBuilder::default()
    }
}

/// A builder for [`ContainerServiceStateDetail`](crate::types::ContainerServiceStateDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ContainerServiceStateDetailBuilder {
    pub(crate) code: ::std::option::Option<crate::types::ContainerServiceStateDetailCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl ContainerServiceStateDetailBuilder {
    /// <p>The state code of the container service.</p>
    /// <p>The following state codes are possible:</p>
    /// <ul>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>DEPLOYING</code> or <code>UPDATING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING_SYSTEM_RESOURCES</code> - The system resources for your container service are being created.</p></li>
    /// <li>
    /// <p><code>CREATING_NETWORK_INFRASTRUCTURE</code> - The network infrastructure for your container service are being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_CERTIFICATE</code> - The SSL/TLS certificate for your container service is being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_SERVICE</code> - Your container service is being provisioned.</p></li>
    /// <li>
    /// <p><code>CREATING_DEPLOYMENT</code> - Your deployment is being created on your container service.</p></li>
    /// <li>
    /// <p><code>EVALUATING_HEALTH_CHECK</code> - The health of your deployment is being evaluated.</p></li>
    /// <li>
    /// <p><code>ACTIVATING_DEPLOYMENT</code> - Your deployment is being activated.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>PENDING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CERTIFICATE_LIMIT_EXCEEDED</code> - The SSL/TLS certificate required for your container service exceeds the maximum number of certificates allowed for your account.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code> - An error was experienced when your container service was being created.</p></li>
    /// </ul></li>
    /// </ul>
    pub fn code(mut self, input: crate::types::ContainerServiceStateDetailCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state code of the container service.</p>
    /// <p>The following state codes are possible:</p>
    /// <ul>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>DEPLOYING</code> or <code>UPDATING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING_SYSTEM_RESOURCES</code> - The system resources for your container service are being created.</p></li>
    /// <li>
    /// <p><code>CREATING_NETWORK_INFRASTRUCTURE</code> - The network infrastructure for your container service are being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_CERTIFICATE</code> - The SSL/TLS certificate for your container service is being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_SERVICE</code> - Your container service is being provisioned.</p></li>
    /// <li>
    /// <p><code>CREATING_DEPLOYMENT</code> - Your deployment is being created on your container service.</p></li>
    /// <li>
    /// <p><code>EVALUATING_HEALTH_CHECK</code> - The health of your deployment is being evaluated.</p></li>
    /// <li>
    /// <p><code>ACTIVATING_DEPLOYMENT</code> - Your deployment is being activated.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>PENDING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CERTIFICATE_LIMIT_EXCEEDED</code> - The SSL/TLS certificate required for your container service exceeds the maximum number of certificates allowed for your account.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code> - An error was experienced when your container service was being created.</p></li>
    /// </ul></li>
    /// </ul>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::ContainerServiceStateDetailCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>The state code of the container service.</p>
    /// <p>The following state codes are possible:</p>
    /// <ul>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>DEPLOYING</code> or <code>UPDATING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CREATING_SYSTEM_RESOURCES</code> - The system resources for your container service are being created.</p></li>
    /// <li>
    /// <p><code>CREATING_NETWORK_INFRASTRUCTURE</code> - The network infrastructure for your container service are being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_CERTIFICATE</code> - The SSL/TLS certificate for your container service is being created.</p></li>
    /// <li>
    /// <p><code>PROVISIONING_SERVICE</code> - Your container service is being provisioned.</p></li>
    /// <li>
    /// <p><code>CREATING_DEPLOYMENT</code> - Your deployment is being created on your container service.</p></li>
    /// <li>
    /// <p><code>EVALUATING_HEALTH_CHECK</code> - The health of your deployment is being evaluated.</p></li>
    /// <li>
    /// <p><code>ACTIVATING_DEPLOYMENT</code> - Your deployment is being activated.</p></li>
    /// </ul></li>
    /// <li>
    /// <p>The following state codes are possible if your container service is in a <code>PENDING</code> state:</p>
    /// <ul>
    /// <li>
    /// <p><code>CERTIFICATE_LIMIT_EXCEEDED</code> - The SSL/TLS certificate required for your container service exceeds the maximum number of certificates allowed for your account.</p></li>
    /// <li>
    /// <p><code>UNKNOWN_ERROR</code> - An error was experienced when your container service was being created.</p></li>
    /// </ul></li>
    /// </ul>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::ContainerServiceStateDetailCode> {
        &self.code
    }
    /// <p>A message that provides more information for the state code.</p><note>
    /// <p>The state detail is populated only when a container service is in a <code>PENDING</code>, <code>DEPLOYING</code>, or <code>UPDATING</code> state.</p>
    /// </note>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A message that provides more information for the state code.</p><note>
    /// <p>The state detail is populated only when a container service is in a <code>PENDING</code>, <code>DEPLOYING</code>, or <code>UPDATING</code> state.</p>
    /// </note>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>A message that provides more information for the state code.</p><note>
    /// <p>The state detail is populated only when a container service is in a <code>PENDING</code>, <code>DEPLOYING</code>, or <code>UPDATING</code> state.</p>
    /// </note>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`ContainerServiceStateDetail`](crate::types::ContainerServiceStateDetail).
    pub fn build(self) -> crate::types::ContainerServiceStateDetail {
        crate::types::ContainerServiceStateDetail {
            code: self.code,
            message: self.message,
        }
    }
}
