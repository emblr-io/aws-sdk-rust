// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateAppInput {
    /// <p>The app ID.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>The app name.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>A description of the app.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>The app's data sources.</p>
    pub data_sources: ::std::option::Option<::std::vec::Vec<crate::types::DataSource>>,
    /// <p>The app type.</p>
    pub r#type: ::std::option::Option<crate::types::AppType>,
    /// <p>A <code>Source</code> object that specifies the app repository.</p>
    pub app_source: ::std::option::Option<crate::types::Source>,
    /// <p>The app's virtual host settings, with multiple domains separated by commas. For example: <code>'www.example.com, example.com'</code></p>
    pub domains: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Whether SSL is enabled for the app.</p>
    pub enable_ssl: ::std::option::Option<bool>,
    /// <p>An <code>SslConfiguration</code> object with the SSL configuration.</p>
    pub ssl_configuration: ::std::option::Option<crate::types::SslConfiguration>,
    /// <p>One or more user-defined key/value pairs to be added to the stack attributes.</p>
    pub attributes: ::std::option::Option<::std::collections::HashMap<crate::types::AppAttributesKeys, ::std::string::String>>,
    /// <p>An array of <code>EnvironmentVariable</code> objects that specify environment variables to be associated with the app. After you deploy the app, these variables are defined on the associated app server instances.For more information, see <a href="https://docs.aws.amazon.com/opsworks/latest/userguide/workingapps-creating.html#workingapps-creating-environment"> Environment Variables</a>.</p>
    /// <p>There is no specific limit on the number of environment variables. However, the size of the associated data structure - which includes the variables' names, values, and protected flag values - cannot exceed 20 KB. This limit should accommodate most if not all use cases. Exceeding it will cause an exception with the message, "Environment: is too large (maximum is 20 KB)."</p><note>
    /// <p>If you have specified one or more environment variables, you cannot modify the stack's Chef version.</p>
    /// </note>
    pub environment: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentVariable>>,
}
impl UpdateAppInput {
    /// <p>The app ID.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>The app name.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>A description of the app.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>The app's data sources.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_sources.is_none()`.
    pub fn data_sources(&self) -> &[crate::types::DataSource] {
        self.data_sources.as_deref().unwrap_or_default()
    }
    /// <p>The app type.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::AppType> {
        self.r#type.as_ref()
    }
    /// <p>A <code>Source</code> object that specifies the app repository.</p>
    pub fn app_source(&self) -> ::std::option::Option<&crate::types::Source> {
        self.app_source.as_ref()
    }
    /// <p>The app's virtual host settings, with multiple domains separated by commas. For example: <code>'www.example.com, example.com'</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.domains.is_none()`.
    pub fn domains(&self) -> &[::std::string::String] {
        self.domains.as_deref().unwrap_or_default()
    }
    /// <p>Whether SSL is enabled for the app.</p>
    pub fn enable_ssl(&self) -> ::std::option::Option<bool> {
        self.enable_ssl
    }
    /// <p>An <code>SslConfiguration</code> object with the SSL configuration.</p>
    pub fn ssl_configuration(&self) -> ::std::option::Option<&crate::types::SslConfiguration> {
        self.ssl_configuration.as_ref()
    }
    /// <p>One or more user-defined key/value pairs to be added to the stack attributes.</p>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<crate::types::AppAttributesKeys, ::std::string::String>> {
        self.attributes.as_ref()
    }
    /// <p>An array of <code>EnvironmentVariable</code> objects that specify environment variables to be associated with the app. After you deploy the app, these variables are defined on the associated app server instances.For more information, see <a href="https://docs.aws.amazon.com/opsworks/latest/userguide/workingapps-creating.html#workingapps-creating-environment"> Environment Variables</a>.</p>
    /// <p>There is no specific limit on the number of environment variables. However, the size of the associated data structure - which includes the variables' names, values, and protected flag values - cannot exceed 20 KB. This limit should accommodate most if not all use cases. Exceeding it will cause an exception with the message, "Environment: is too large (maximum is 20 KB)."</p><note>
    /// <p>If you have specified one or more environment variables, you cannot modify the stack's Chef version.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.environment.is_none()`.
    pub fn environment(&self) -> &[crate::types::EnvironmentVariable] {
        self.environment.as_deref().unwrap_or_default()
    }
}
impl UpdateAppInput {
    /// Creates a new builder-style object to manufacture [`UpdateAppInput`](crate::operation::update_app::UpdateAppInput).
    pub fn builder() -> crate::operation::update_app::builders::UpdateAppInputBuilder {
        crate::operation::update_app::builders::UpdateAppInputBuilder::default()
    }
}

/// A builder for [`UpdateAppInput`](crate::operation::update_app::UpdateAppInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateAppInputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) data_sources: ::std::option::Option<::std::vec::Vec<crate::types::DataSource>>,
    pub(crate) r#type: ::std::option::Option<crate::types::AppType>,
    pub(crate) app_source: ::std::option::Option<crate::types::Source>,
    pub(crate) domains: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) enable_ssl: ::std::option::Option<bool>,
    pub(crate) ssl_configuration: ::std::option::Option<crate::types::SslConfiguration>,
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<crate::types::AppAttributesKeys, ::std::string::String>>,
    pub(crate) environment: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentVariable>>,
}
impl UpdateAppInputBuilder {
    /// <p>The app ID.</p>
    /// This field is required.
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The app ID.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The app ID.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The app name.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The app name.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The app name.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>A description of the app.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description of the app.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description of the app.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `data_sources`.
    ///
    /// To override the contents of this collection use [`set_data_sources`](Self::set_data_sources).
    ///
    /// <p>The app's data sources.</p>
    pub fn data_sources(mut self, input: crate::types::DataSource) -> Self {
        let mut v = self.data_sources.unwrap_or_default();
        v.push(input);
        self.data_sources = ::std::option::Option::Some(v);
        self
    }
    /// <p>The app's data sources.</p>
    pub fn set_data_sources(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataSource>>) -> Self {
        self.data_sources = input;
        self
    }
    /// <p>The app's data sources.</p>
    pub fn get_data_sources(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataSource>> {
        &self.data_sources
    }
    /// <p>The app type.</p>
    pub fn r#type(mut self, input: crate::types::AppType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The app type.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::AppType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The app type.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::AppType> {
        &self.r#type
    }
    /// <p>A <code>Source</code> object that specifies the app repository.</p>
    pub fn app_source(mut self, input: crate::types::Source) -> Self {
        self.app_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>A <code>Source</code> object that specifies the app repository.</p>
    pub fn set_app_source(mut self, input: ::std::option::Option<crate::types::Source>) -> Self {
        self.app_source = input;
        self
    }
    /// <p>A <code>Source</code> object that specifies the app repository.</p>
    pub fn get_app_source(&self) -> &::std::option::Option<crate::types::Source> {
        &self.app_source
    }
    /// Appends an item to `domains`.
    ///
    /// To override the contents of this collection use [`set_domains`](Self::set_domains).
    ///
    /// <p>The app's virtual host settings, with multiple domains separated by commas. For example: <code>'www.example.com, example.com'</code></p>
    pub fn domains(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.domains.unwrap_or_default();
        v.push(input.into());
        self.domains = ::std::option::Option::Some(v);
        self
    }
    /// <p>The app's virtual host settings, with multiple domains separated by commas. For example: <code>'www.example.com, example.com'</code></p>
    pub fn set_domains(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.domains = input;
        self
    }
    /// <p>The app's virtual host settings, with multiple domains separated by commas. For example: <code>'www.example.com, example.com'</code></p>
    pub fn get_domains(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.domains
    }
    /// <p>Whether SSL is enabled for the app.</p>
    pub fn enable_ssl(mut self, input: bool) -> Self {
        self.enable_ssl = ::std::option::Option::Some(input);
        self
    }
    /// <p>Whether SSL is enabled for the app.</p>
    pub fn set_enable_ssl(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_ssl = input;
        self
    }
    /// <p>Whether SSL is enabled for the app.</p>
    pub fn get_enable_ssl(&self) -> &::std::option::Option<bool> {
        &self.enable_ssl
    }
    /// <p>An <code>SslConfiguration</code> object with the SSL configuration.</p>
    pub fn ssl_configuration(mut self, input: crate::types::SslConfiguration) -> Self {
        self.ssl_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>An <code>SslConfiguration</code> object with the SSL configuration.</p>
    pub fn set_ssl_configuration(mut self, input: ::std::option::Option<crate::types::SslConfiguration>) -> Self {
        self.ssl_configuration = input;
        self
    }
    /// <p>An <code>SslConfiguration</code> object with the SSL configuration.</p>
    pub fn get_ssl_configuration(&self) -> &::std::option::Option<crate::types::SslConfiguration> {
        &self.ssl_configuration
    }
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>One or more user-defined key/value pairs to be added to the stack attributes.</p>
    pub fn attributes(mut self, k: crate::types::AppAttributesKeys, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k, v.into());
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>One or more user-defined key/value pairs to be added to the stack attributes.</p>
    pub fn set_attributes(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<crate::types::AppAttributesKeys, ::std::string::String>>,
    ) -> Self {
        self.attributes = input;
        self
    }
    /// <p>One or more user-defined key/value pairs to be added to the stack attributes.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<crate::types::AppAttributesKeys, ::std::string::String>> {
        &self.attributes
    }
    /// Appends an item to `environment`.
    ///
    /// To override the contents of this collection use [`set_environment`](Self::set_environment).
    ///
    /// <p>An array of <code>EnvironmentVariable</code> objects that specify environment variables to be associated with the app. After you deploy the app, these variables are defined on the associated app server instances.For more information, see <a href="https://docs.aws.amazon.com/opsworks/latest/userguide/workingapps-creating.html#workingapps-creating-environment"> Environment Variables</a>.</p>
    /// <p>There is no specific limit on the number of environment variables. However, the size of the associated data structure - which includes the variables' names, values, and protected flag values - cannot exceed 20 KB. This limit should accommodate most if not all use cases. Exceeding it will cause an exception with the message, "Environment: is too large (maximum is 20 KB)."</p><note>
    /// <p>If you have specified one or more environment variables, you cannot modify the stack's Chef version.</p>
    /// </note>
    pub fn environment(mut self, input: crate::types::EnvironmentVariable) -> Self {
        let mut v = self.environment.unwrap_or_default();
        v.push(input);
        self.environment = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>EnvironmentVariable</code> objects that specify environment variables to be associated with the app. After you deploy the app, these variables are defined on the associated app server instances.For more information, see <a href="https://docs.aws.amazon.com/opsworks/latest/userguide/workingapps-creating.html#workingapps-creating-environment"> Environment Variables</a>.</p>
    /// <p>There is no specific limit on the number of environment variables. However, the size of the associated data structure - which includes the variables' names, values, and protected flag values - cannot exceed 20 KB. This limit should accommodate most if not all use cases. Exceeding it will cause an exception with the message, "Environment: is too large (maximum is 20 KB)."</p><note>
    /// <p>If you have specified one or more environment variables, you cannot modify the stack's Chef version.</p>
    /// </note>
    pub fn set_environment(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::EnvironmentVariable>>) -> Self {
        self.environment = input;
        self
    }
    /// <p>An array of <code>EnvironmentVariable</code> objects that specify environment variables to be associated with the app. After you deploy the app, these variables are defined on the associated app server instances.For more information, see <a href="https://docs.aws.amazon.com/opsworks/latest/userguide/workingapps-creating.html#workingapps-creating-environment"> Environment Variables</a>.</p>
    /// <p>There is no specific limit on the number of environment variables. However, the size of the associated data structure - which includes the variables' names, values, and protected flag values - cannot exceed 20 KB. This limit should accommodate most if not all use cases. Exceeding it will cause an exception with the message, "Environment: is too large (maximum is 20 KB)."</p><note>
    /// <p>If you have specified one or more environment variables, you cannot modify the stack's Chef version.</p>
    /// </note>
    pub fn get_environment(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::EnvironmentVariable>> {
        &self.environment
    }
    /// Consumes the builder and constructs a [`UpdateAppInput`](crate::operation::update_app::UpdateAppInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::update_app::UpdateAppInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_app::UpdateAppInput {
            app_id: self.app_id,
            name: self.name,
            description: self.description,
            data_sources: self.data_sources,
            r#type: self.r#type,
            app_source: self.app_source,
            domains: self.domains,
            enable_ssl: self.enable_ssl,
            ssl_configuration: self.ssl_configuration,
            attributes: self.attributes,
            environment: self.environment,
        })
    }
}
