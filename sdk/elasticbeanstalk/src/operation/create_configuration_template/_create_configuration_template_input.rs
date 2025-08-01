// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Request to create a configuration template.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateConfigurationTemplateInput {
    /// <p>The name of the Elastic Beanstalk application to associate with this configuration template.</p>
    pub application_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of the configuration template.</p>
    /// <p>Constraint: This name must be unique per application.</p>
    pub template_name: ::std::option::Option<::std::string::String>,
    /// <p>The name of an Elastic Beanstalk solution stack (platform version) that this configuration uses. For example, <code>64bit Amazon Linux 2013.09 running Tomcat 7 Java 7</code>. A solution stack specifies the operating system, runtime, and application server for a configuration template. It also determines the set of configuration options as well as the possible and default values. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/concepts.platforms.html">Supported Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    /// <p>You must specify <code>SolutionStackName</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SourceConfiguration</code>.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ListAvailableSolutionStacks.html"> <code>ListAvailableSolutionStacks</code> </a> API to obtain a list of available solution stacks.</p>
    pub solution_stack_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the custom platform. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/custom-platforms.html"> Custom Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p><note>
    /// <p>If you specify <code>PlatformArn</code>, then don't specify <code>SolutionStackName</code>.</p>
    /// </note>
    pub platform_arn: ::std::option::Option<::std::string::String>,
    /// <p>An Elastic Beanstalk configuration template to base this one on. If specified, Elastic Beanstalk uses the configuration values from the specified configuration template to create a new configuration.</p>
    /// <p>Values specified in <code>OptionSettings</code> override any values obtained from the <code>SourceConfiguration</code>.</p>
    /// <p>You must specify <code>SourceConfiguration</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SolutionStackName</code>.</p>
    /// <p>Constraint: If both solution stack name and source configuration are specified, the solution stack of the source configuration template must match the specified solution stack name.</p>
    pub source_configuration: ::std::option::Option<crate::types::SourceConfiguration>,
    /// <p>The ID of an environment whose settings you want to use to create the configuration template. You must specify <code>EnvironmentId</code> if you don't specify <code>PlatformArn</code>, <code>SolutionStackName</code>, or <code>SourceConfiguration</code>.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>An optional description for this configuration.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Option values for the Elastic Beanstalk configuration, such as the instance type. If specified, these values override the values obtained from the solution stack or the source configuration template. For a complete list of Elastic Beanstalk configuration options, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options.html">Option Values</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    pub option_settings: ::std::option::Option<::std::vec::Vec<crate::types::ConfigurationOptionSetting>>,
    /// <p>Specifies the tags applied to the configuration template.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateConfigurationTemplateInput {
    /// <p>The name of the Elastic Beanstalk application to associate with this configuration template.</p>
    pub fn application_name(&self) -> ::std::option::Option<&str> {
        self.application_name.as_deref()
    }
    /// <p>The name of the configuration template.</p>
    /// <p>Constraint: This name must be unique per application.</p>
    pub fn template_name(&self) -> ::std::option::Option<&str> {
        self.template_name.as_deref()
    }
    /// <p>The name of an Elastic Beanstalk solution stack (platform version) that this configuration uses. For example, <code>64bit Amazon Linux 2013.09 running Tomcat 7 Java 7</code>. A solution stack specifies the operating system, runtime, and application server for a configuration template. It also determines the set of configuration options as well as the possible and default values. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/concepts.platforms.html">Supported Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    /// <p>You must specify <code>SolutionStackName</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SourceConfiguration</code>.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ListAvailableSolutionStacks.html"> <code>ListAvailableSolutionStacks</code> </a> API to obtain a list of available solution stacks.</p>
    pub fn solution_stack_name(&self) -> ::std::option::Option<&str> {
        self.solution_stack_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the custom platform. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/custom-platforms.html"> Custom Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p><note>
    /// <p>If you specify <code>PlatformArn</code>, then don't specify <code>SolutionStackName</code>.</p>
    /// </note>
    pub fn platform_arn(&self) -> ::std::option::Option<&str> {
        self.platform_arn.as_deref()
    }
    /// <p>An Elastic Beanstalk configuration template to base this one on. If specified, Elastic Beanstalk uses the configuration values from the specified configuration template to create a new configuration.</p>
    /// <p>Values specified in <code>OptionSettings</code> override any values obtained from the <code>SourceConfiguration</code>.</p>
    /// <p>You must specify <code>SourceConfiguration</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SolutionStackName</code>.</p>
    /// <p>Constraint: If both solution stack name and source configuration are specified, the solution stack of the source configuration template must match the specified solution stack name.</p>
    pub fn source_configuration(&self) -> ::std::option::Option<&crate::types::SourceConfiguration> {
        self.source_configuration.as_ref()
    }
    /// <p>The ID of an environment whose settings you want to use to create the configuration template. You must specify <code>EnvironmentId</code> if you don't specify <code>PlatformArn</code>, <code>SolutionStackName</code>, or <code>SourceConfiguration</code>.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>An optional description for this configuration.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Option values for the Elastic Beanstalk configuration, such as the instance type. If specified, these values override the values obtained from the solution stack or the source configuration template. For a complete list of Elastic Beanstalk configuration options, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options.html">Option Values</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.option_settings.is_none()`.
    pub fn option_settings(&self) -> &[crate::types::ConfigurationOptionSetting] {
        self.option_settings.as_deref().unwrap_or_default()
    }
    /// <p>Specifies the tags applied to the configuration template.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateConfigurationTemplateInput {
    /// Creates a new builder-style object to manufacture [`CreateConfigurationTemplateInput`](crate::operation::create_configuration_template::CreateConfigurationTemplateInput).
    pub fn builder() -> crate::operation::create_configuration_template::builders::CreateConfigurationTemplateInputBuilder {
        crate::operation::create_configuration_template::builders::CreateConfigurationTemplateInputBuilder::default()
    }
}

/// A builder for [`CreateConfigurationTemplateInput`](crate::operation::create_configuration_template::CreateConfigurationTemplateInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateConfigurationTemplateInputBuilder {
    pub(crate) application_name: ::std::option::Option<::std::string::String>,
    pub(crate) template_name: ::std::option::Option<::std::string::String>,
    pub(crate) solution_stack_name: ::std::option::Option<::std::string::String>,
    pub(crate) platform_arn: ::std::option::Option<::std::string::String>,
    pub(crate) source_configuration: ::std::option::Option<crate::types::SourceConfiguration>,
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) option_settings: ::std::option::Option<::std::vec::Vec<crate::types::ConfigurationOptionSetting>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateConfigurationTemplateInputBuilder {
    /// <p>The name of the Elastic Beanstalk application to associate with this configuration template.</p>
    /// This field is required.
    pub fn application_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Elastic Beanstalk application to associate with this configuration template.</p>
    pub fn set_application_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_name = input;
        self
    }
    /// <p>The name of the Elastic Beanstalk application to associate with this configuration template.</p>
    pub fn get_application_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_name
    }
    /// <p>The name of the configuration template.</p>
    /// <p>Constraint: This name must be unique per application.</p>
    /// This field is required.
    pub fn template_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.template_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration template.</p>
    /// <p>Constraint: This name must be unique per application.</p>
    pub fn set_template_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.template_name = input;
        self
    }
    /// <p>The name of the configuration template.</p>
    /// <p>Constraint: This name must be unique per application.</p>
    pub fn get_template_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.template_name
    }
    /// <p>The name of an Elastic Beanstalk solution stack (platform version) that this configuration uses. For example, <code>64bit Amazon Linux 2013.09 running Tomcat 7 Java 7</code>. A solution stack specifies the operating system, runtime, and application server for a configuration template. It also determines the set of configuration options as well as the possible and default values. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/concepts.platforms.html">Supported Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    /// <p>You must specify <code>SolutionStackName</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SourceConfiguration</code>.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ListAvailableSolutionStacks.html"> <code>ListAvailableSolutionStacks</code> </a> API to obtain a list of available solution stacks.</p>
    pub fn solution_stack_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.solution_stack_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of an Elastic Beanstalk solution stack (platform version) that this configuration uses. For example, <code>64bit Amazon Linux 2013.09 running Tomcat 7 Java 7</code>. A solution stack specifies the operating system, runtime, and application server for a configuration template. It also determines the set of configuration options as well as the possible and default values. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/concepts.platforms.html">Supported Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    /// <p>You must specify <code>SolutionStackName</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SourceConfiguration</code>.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ListAvailableSolutionStacks.html"> <code>ListAvailableSolutionStacks</code> </a> API to obtain a list of available solution stacks.</p>
    pub fn set_solution_stack_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.solution_stack_name = input;
        self
    }
    /// <p>The name of an Elastic Beanstalk solution stack (platform version) that this configuration uses. For example, <code>64bit Amazon Linux 2013.09 running Tomcat 7 Java 7</code>. A solution stack specifies the operating system, runtime, and application server for a configuration template. It also determines the set of configuration options as well as the possible and default values. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/concepts.platforms.html">Supported Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    /// <p>You must specify <code>SolutionStackName</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SourceConfiguration</code>.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/api/API_ListAvailableSolutionStacks.html"> <code>ListAvailableSolutionStacks</code> </a> API to obtain a list of available solution stacks.</p>
    pub fn get_solution_stack_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.solution_stack_name
    }
    /// <p>The Amazon Resource Name (ARN) of the custom platform. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/custom-platforms.html"> Custom Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p><note>
    /// <p>If you specify <code>PlatformArn</code>, then don't specify <code>SolutionStackName</code>.</p>
    /// </note>
    pub fn platform_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom platform. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/custom-platforms.html"> Custom Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p><note>
    /// <p>If you specify <code>PlatformArn</code>, then don't specify <code>SolutionStackName</code>.</p>
    /// </note>
    pub fn set_platform_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the custom platform. For more information, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/custom-platforms.html"> Custom Platforms</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p><note>
    /// <p>If you specify <code>PlatformArn</code>, then don't specify <code>SolutionStackName</code>.</p>
    /// </note>
    pub fn get_platform_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform_arn
    }
    /// <p>An Elastic Beanstalk configuration template to base this one on. If specified, Elastic Beanstalk uses the configuration values from the specified configuration template to create a new configuration.</p>
    /// <p>Values specified in <code>OptionSettings</code> override any values obtained from the <code>SourceConfiguration</code>.</p>
    /// <p>You must specify <code>SourceConfiguration</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SolutionStackName</code>.</p>
    /// <p>Constraint: If both solution stack name and source configuration are specified, the solution stack of the source configuration template must match the specified solution stack name.</p>
    pub fn source_configuration(mut self, input: crate::types::SourceConfiguration) -> Self {
        self.source_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>An Elastic Beanstalk configuration template to base this one on. If specified, Elastic Beanstalk uses the configuration values from the specified configuration template to create a new configuration.</p>
    /// <p>Values specified in <code>OptionSettings</code> override any values obtained from the <code>SourceConfiguration</code>.</p>
    /// <p>You must specify <code>SourceConfiguration</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SolutionStackName</code>.</p>
    /// <p>Constraint: If both solution stack name and source configuration are specified, the solution stack of the source configuration template must match the specified solution stack name.</p>
    pub fn set_source_configuration(mut self, input: ::std::option::Option<crate::types::SourceConfiguration>) -> Self {
        self.source_configuration = input;
        self
    }
    /// <p>An Elastic Beanstalk configuration template to base this one on. If specified, Elastic Beanstalk uses the configuration values from the specified configuration template to create a new configuration.</p>
    /// <p>Values specified in <code>OptionSettings</code> override any values obtained from the <code>SourceConfiguration</code>.</p>
    /// <p>You must specify <code>SourceConfiguration</code> if you don't specify <code>PlatformArn</code>, <code>EnvironmentId</code>, or <code>SolutionStackName</code>.</p>
    /// <p>Constraint: If both solution stack name and source configuration are specified, the solution stack of the source configuration template must match the specified solution stack name.</p>
    pub fn get_source_configuration(&self) -> &::std::option::Option<crate::types::SourceConfiguration> {
        &self.source_configuration
    }
    /// <p>The ID of an environment whose settings you want to use to create the configuration template. You must specify <code>EnvironmentId</code> if you don't specify <code>PlatformArn</code>, <code>SolutionStackName</code>, or <code>SourceConfiguration</code>.</p>
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of an environment whose settings you want to use to create the configuration template. You must specify <code>EnvironmentId</code> if you don't specify <code>PlatformArn</code>, <code>SolutionStackName</code>, or <code>SourceConfiguration</code>.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>The ID of an environment whose settings you want to use to create the configuration template. You must specify <code>EnvironmentId</code> if you don't specify <code>PlatformArn</code>, <code>SolutionStackName</code>, or <code>SourceConfiguration</code>.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// <p>An optional description for this configuration.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional description for this configuration.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>An optional description for this configuration.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `option_settings`.
    ///
    /// To override the contents of this collection use [`set_option_settings`](Self::set_option_settings).
    ///
    /// <p>Option values for the Elastic Beanstalk configuration, such as the instance type. If specified, these values override the values obtained from the solution stack or the source configuration template. For a complete list of Elastic Beanstalk configuration options, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options.html">Option Values</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    pub fn option_settings(mut self, input: crate::types::ConfigurationOptionSetting) -> Self {
        let mut v = self.option_settings.unwrap_or_default();
        v.push(input);
        self.option_settings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Option values for the Elastic Beanstalk configuration, such as the instance type. If specified, these values override the values obtained from the solution stack or the source configuration template. For a complete list of Elastic Beanstalk configuration options, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options.html">Option Values</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    pub fn set_option_settings(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ConfigurationOptionSetting>>) -> Self {
        self.option_settings = input;
        self
    }
    /// <p>Option values for the Elastic Beanstalk configuration, such as the instance type. If specified, these values override the values obtained from the solution stack or the source configuration template. For a complete list of Elastic Beanstalk configuration options, see <a href="https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options.html">Option Values</a> in the <i>AWS Elastic Beanstalk Developer Guide</i>.</p>
    pub fn get_option_settings(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ConfigurationOptionSetting>> {
        &self.option_settings
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Specifies the tags applied to the configuration template.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the tags applied to the configuration template.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Specifies the tags applied to the configuration template.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateConfigurationTemplateInput`](crate::operation::create_configuration_template::CreateConfigurationTemplateInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_configuration_template::CreateConfigurationTemplateInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_configuration_template::CreateConfigurationTemplateInput {
            application_name: self.application_name,
            template_name: self.template_name,
            solution_stack_name: self.solution_stack_name,
            platform_arn: self.platform_arn,
            source_configuration: self.source_configuration,
            environment_id: self.environment_id,
            description: self.description,
            option_settings: self.option_settings,
            tags: self.tags,
        })
    }
}
