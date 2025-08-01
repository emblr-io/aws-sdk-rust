// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about the tier of the environment.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsElasticBeanstalkEnvironmentTier {
    /// <p>The name of the environment tier. Valid values are <code>WebServer</code> or <code>Worker</code>.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The type of environment tier. Valid values are <code>Standard</code> or <code>SQS/HTTP</code>.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>The version of the environment tier.</p>
    pub version: ::std::option::Option<::std::string::String>,
}
impl AwsElasticBeanstalkEnvironmentTier {
    /// <p>The name of the environment tier. Valid values are <code>WebServer</code> or <code>Worker</code>.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The type of environment tier. Valid values are <code>Standard</code> or <code>SQS/HTTP</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>The version of the environment tier.</p>
    pub fn version(&self) -> ::std::option::Option<&str> {
        self.version.as_deref()
    }
}
impl AwsElasticBeanstalkEnvironmentTier {
    /// Creates a new builder-style object to manufacture [`AwsElasticBeanstalkEnvironmentTier`](crate::types::AwsElasticBeanstalkEnvironmentTier).
    pub fn builder() -> crate::types::builders::AwsElasticBeanstalkEnvironmentTierBuilder {
        crate::types::builders::AwsElasticBeanstalkEnvironmentTierBuilder::default()
    }
}

/// A builder for [`AwsElasticBeanstalkEnvironmentTier`](crate::types::AwsElasticBeanstalkEnvironmentTier).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsElasticBeanstalkEnvironmentTierBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) version: ::std::option::Option<::std::string::String>,
}
impl AwsElasticBeanstalkEnvironmentTierBuilder {
    /// <p>The name of the environment tier. Valid values are <code>WebServer</code> or <code>Worker</code>.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the environment tier. Valid values are <code>WebServer</code> or <code>Worker</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the environment tier. Valid values are <code>WebServer</code> or <code>Worker</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The type of environment tier. Valid values are <code>Standard</code> or <code>SQS/HTTP</code>.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of environment tier. Valid values are <code>Standard</code> or <code>SQS/HTTP</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of environment tier. Valid values are <code>Standard</code> or <code>SQS/HTTP</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>The version of the environment tier.</p>
    pub fn version(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.version = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version of the environment tier.</p>
    pub fn set_version(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.version = input;
        self
    }
    /// <p>The version of the environment tier.</p>
    pub fn get_version(&self) -> &::std::option::Option<::std::string::String> {
        &self.version
    }
    /// Consumes the builder and constructs a [`AwsElasticBeanstalkEnvironmentTier`](crate::types::AwsElasticBeanstalkEnvironmentTier).
    pub fn build(self) -> crate::types::AwsElasticBeanstalkEnvironmentTier {
        crate::types::AwsElasticBeanstalkEnvironmentTier {
            name: self.name,
            r#type: self.r#type,
            version: self.version,
        }
    }
}
