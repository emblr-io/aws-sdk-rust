// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetConfigurationInput {
    /// <p>The application to get. Specify either the application name or the application ID.</p>
    pub application: ::std::option::Option<::std::string::String>,
    /// <p>The environment to get. Specify either the environment name or the environment ID.</p>
    pub environment: ::std::option::Option<::std::string::String>,
    /// <p>The configuration to get. Specify either the configuration name or the configuration ID.</p>
    pub configuration: ::std::option::Option<::std::string::String>,
    /// <p>The clientId parameter in the following command is a unique, user-specified ID to identify the client for the configuration. This ID enables AppConfig to deploy the configuration in intervals, as defined in the deployment strategy.</p>
    pub client_id: ::std::option::Option<::std::string::String>,
    /// <p>The configuration version returned in the most recent <code>GetConfiguration</code> response.</p><important>
    /// <p>AppConfig uses the value of the <code>ClientConfigurationVersion</code> parameter to identify the configuration version on your clients. If you don’t send <code>ClientConfigurationVersion</code> with each call to <code>GetConfiguration</code>, your clients receive the current configuration. You are charged each time your clients receive a configuration.</p>
    /// <p>To avoid excess charges, we recommend you use the <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/StartConfigurationSession.html">StartConfigurationSession</a> and <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/GetLatestConfiguration.html">GetLatestConfiguration</a> APIs, which track the client configuration version on your behalf. If you choose to continue using <code>GetConfiguration</code>, we recommend that you include the <code>ClientConfigurationVersion</code> value with every call to <code>GetConfiguration</code>. The value to use for <code>ClientConfigurationVersion</code> comes from the <code>ConfigurationVersion</code> attribute returned by <code>GetConfiguration</code> when there is new or updated data, and should be saved for subsequent calls to <code>GetConfiguration</code>.</p>
    /// </important>
    /// <p>For more information about working with configurations, see <a href="http://docs.aws.amazon.com/appconfig/latest/userguide/retrieving-feature-flags.html">Retrieving feature flags and configuration data in AppConfig</a> in the <i>AppConfig User Guide</i>.</p>
    pub client_configuration_version: ::std::option::Option<::std::string::String>,
}
impl GetConfigurationInput {
    /// <p>The application to get. Specify either the application name or the application ID.</p>
    pub fn application(&self) -> ::std::option::Option<&str> {
        self.application.as_deref()
    }
    /// <p>The environment to get. Specify either the environment name or the environment ID.</p>
    pub fn environment(&self) -> ::std::option::Option<&str> {
        self.environment.as_deref()
    }
    /// <p>The configuration to get. Specify either the configuration name or the configuration ID.</p>
    pub fn configuration(&self) -> ::std::option::Option<&str> {
        self.configuration.as_deref()
    }
    /// <p>The clientId parameter in the following command is a unique, user-specified ID to identify the client for the configuration. This ID enables AppConfig to deploy the configuration in intervals, as defined in the deployment strategy.</p>
    pub fn client_id(&self) -> ::std::option::Option<&str> {
        self.client_id.as_deref()
    }
    /// <p>The configuration version returned in the most recent <code>GetConfiguration</code> response.</p><important>
    /// <p>AppConfig uses the value of the <code>ClientConfigurationVersion</code> parameter to identify the configuration version on your clients. If you don’t send <code>ClientConfigurationVersion</code> with each call to <code>GetConfiguration</code>, your clients receive the current configuration. You are charged each time your clients receive a configuration.</p>
    /// <p>To avoid excess charges, we recommend you use the <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/StartConfigurationSession.html">StartConfigurationSession</a> and <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/GetLatestConfiguration.html">GetLatestConfiguration</a> APIs, which track the client configuration version on your behalf. If you choose to continue using <code>GetConfiguration</code>, we recommend that you include the <code>ClientConfigurationVersion</code> value with every call to <code>GetConfiguration</code>. The value to use for <code>ClientConfigurationVersion</code> comes from the <code>ConfigurationVersion</code> attribute returned by <code>GetConfiguration</code> when there is new or updated data, and should be saved for subsequent calls to <code>GetConfiguration</code>.</p>
    /// </important>
    /// <p>For more information about working with configurations, see <a href="http://docs.aws.amazon.com/appconfig/latest/userguide/retrieving-feature-flags.html">Retrieving feature flags and configuration data in AppConfig</a> in the <i>AppConfig User Guide</i>.</p>
    pub fn client_configuration_version(&self) -> ::std::option::Option<&str> {
        self.client_configuration_version.as_deref()
    }
}
impl GetConfigurationInput {
    /// Creates a new builder-style object to manufacture [`GetConfigurationInput`](crate::operation::get_configuration::GetConfigurationInput).
    pub fn builder() -> crate::operation::get_configuration::builders::GetConfigurationInputBuilder {
        crate::operation::get_configuration::builders::GetConfigurationInputBuilder::default()
    }
}

/// A builder for [`GetConfigurationInput`](crate::operation::get_configuration::GetConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetConfigurationInputBuilder {
    pub(crate) application: ::std::option::Option<::std::string::String>,
    pub(crate) environment: ::std::option::Option<::std::string::String>,
    pub(crate) configuration: ::std::option::Option<::std::string::String>,
    pub(crate) client_id: ::std::option::Option<::std::string::String>,
    pub(crate) client_configuration_version: ::std::option::Option<::std::string::String>,
}
impl GetConfigurationInputBuilder {
    /// <p>The application to get. Specify either the application name or the application ID.</p>
    /// This field is required.
    pub fn application(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The application to get. Specify either the application name or the application ID.</p>
    pub fn set_application(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application = input;
        self
    }
    /// <p>The application to get. Specify either the application name or the application ID.</p>
    pub fn get_application(&self) -> &::std::option::Option<::std::string::String> {
        &self.application
    }
    /// <p>The environment to get. Specify either the environment name or the environment ID.</p>
    /// This field is required.
    pub fn environment(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The environment to get. Specify either the environment name or the environment ID.</p>
    pub fn set_environment(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment = input;
        self
    }
    /// <p>The environment to get. Specify either the environment name or the environment ID.</p>
    pub fn get_environment(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment
    }
    /// <p>The configuration to get. Specify either the configuration name or the configuration ID.</p>
    /// This field is required.
    pub fn configuration(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The configuration to get. Specify either the configuration name or the configuration ID.</p>
    pub fn set_configuration(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration = input;
        self
    }
    /// <p>The configuration to get. Specify either the configuration name or the configuration ID.</p>
    pub fn get_configuration(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration
    }
    /// <p>The clientId parameter in the following command is a unique, user-specified ID to identify the client for the configuration. This ID enables AppConfig to deploy the configuration in intervals, as defined in the deployment strategy.</p>
    /// This field is required.
    pub fn client_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The clientId parameter in the following command is a unique, user-specified ID to identify the client for the configuration. This ID enables AppConfig to deploy the configuration in intervals, as defined in the deployment strategy.</p>
    pub fn set_client_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_id = input;
        self
    }
    /// <p>The clientId parameter in the following command is a unique, user-specified ID to identify the client for the configuration. This ID enables AppConfig to deploy the configuration in intervals, as defined in the deployment strategy.</p>
    pub fn get_client_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_id
    }
    /// <p>The configuration version returned in the most recent <code>GetConfiguration</code> response.</p><important>
    /// <p>AppConfig uses the value of the <code>ClientConfigurationVersion</code> parameter to identify the configuration version on your clients. If you don’t send <code>ClientConfigurationVersion</code> with each call to <code>GetConfiguration</code>, your clients receive the current configuration. You are charged each time your clients receive a configuration.</p>
    /// <p>To avoid excess charges, we recommend you use the <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/StartConfigurationSession.html">StartConfigurationSession</a> and <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/GetLatestConfiguration.html">GetLatestConfiguration</a> APIs, which track the client configuration version on your behalf. If you choose to continue using <code>GetConfiguration</code>, we recommend that you include the <code>ClientConfigurationVersion</code> value with every call to <code>GetConfiguration</code>. The value to use for <code>ClientConfigurationVersion</code> comes from the <code>ConfigurationVersion</code> attribute returned by <code>GetConfiguration</code> when there is new or updated data, and should be saved for subsequent calls to <code>GetConfiguration</code>.</p>
    /// </important>
    /// <p>For more information about working with configurations, see <a href="http://docs.aws.amazon.com/appconfig/latest/userguide/retrieving-feature-flags.html">Retrieving feature flags and configuration data in AppConfig</a> in the <i>AppConfig User Guide</i>.</p>
    pub fn client_configuration_version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_configuration_version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The configuration version returned in the most recent <code>GetConfiguration</code> response.</p><important>
    /// <p>AppConfig uses the value of the <code>ClientConfigurationVersion</code> parameter to identify the configuration version on your clients. If you don’t send <code>ClientConfigurationVersion</code> with each call to <code>GetConfiguration</code>, your clients receive the current configuration. You are charged each time your clients receive a configuration.</p>
    /// <p>To avoid excess charges, we recommend you use the <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/StartConfigurationSession.html">StartConfigurationSession</a> and <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/GetLatestConfiguration.html">GetLatestConfiguration</a> APIs, which track the client configuration version on your behalf. If you choose to continue using <code>GetConfiguration</code>, we recommend that you include the <code>ClientConfigurationVersion</code> value with every call to <code>GetConfiguration</code>. The value to use for <code>ClientConfigurationVersion</code> comes from the <code>ConfigurationVersion</code> attribute returned by <code>GetConfiguration</code> when there is new or updated data, and should be saved for subsequent calls to <code>GetConfiguration</code>.</p>
    /// </important>
    /// <p>For more information about working with configurations, see <a href="http://docs.aws.amazon.com/appconfig/latest/userguide/retrieving-feature-flags.html">Retrieving feature flags and configuration data in AppConfig</a> in the <i>AppConfig User Guide</i>.</p>
    pub fn set_client_configuration_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_configuration_version = input;
        self
    }
    /// <p>The configuration version returned in the most recent <code>GetConfiguration</code> response.</p><important>
    /// <p>AppConfig uses the value of the <code>ClientConfigurationVersion</code> parameter to identify the configuration version on your clients. If you don’t send <code>ClientConfigurationVersion</code> with each call to <code>GetConfiguration</code>, your clients receive the current configuration. You are charged each time your clients receive a configuration.</p>
    /// <p>To avoid excess charges, we recommend you use the <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/StartConfigurationSession.html">StartConfigurationSession</a> and <a href="https://docs.aws.amazon.com/appconfig/2019-10-09/APIReference/GetLatestConfiguration.html">GetLatestConfiguration</a> APIs, which track the client configuration version on your behalf. If you choose to continue using <code>GetConfiguration</code>, we recommend that you include the <code>ClientConfigurationVersion</code> value with every call to <code>GetConfiguration</code>. The value to use for <code>ClientConfigurationVersion</code> comes from the <code>ConfigurationVersion</code> attribute returned by <code>GetConfiguration</code> when there is new or updated data, and should be saved for subsequent calls to <code>GetConfiguration</code>.</p>
    /// </important>
    /// <p>For more information about working with configurations, see <a href="http://docs.aws.amazon.com/appconfig/latest/userguide/retrieving-feature-flags.html">Retrieving feature flags and configuration data in AppConfig</a> in the <i>AppConfig User Guide</i>.</p>
    pub fn get_client_configuration_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_configuration_version
    }
    /// Consumes the builder and constructs a [`GetConfigurationInput`](crate::operation::get_configuration::GetConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_configuration::GetConfigurationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_configuration::GetConfigurationInput {
            application: self.application,
            environment: self.environment,
            configuration: self.configuration,
            client_id: self.client_id,
            client_configuration_version: self.client_configuration_version,
        })
    }
}
