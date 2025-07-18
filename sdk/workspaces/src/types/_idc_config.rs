// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the configurations of the identity center.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IdcConfig {
    /// <p>The Amazon Resource Name (ARN) of the identity center instance.</p>
    pub instance_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub application_arn: ::std::option::Option<::std::string::String>,
}
impl IdcConfig {
    /// <p>The Amazon Resource Name (ARN) of the identity center instance.</p>
    pub fn instance_arn(&self) -> ::std::option::Option<&str> {
        self.instance_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn application_arn(&self) -> ::std::option::Option<&str> {
        self.application_arn.as_deref()
    }
}
impl IdcConfig {
    /// Creates a new builder-style object to manufacture [`IdcConfig`](crate::types::IdcConfig).
    pub fn builder() -> crate::types::builders::IdcConfigBuilder {
        crate::types::builders::IdcConfigBuilder::default()
    }
}

/// A builder for [`IdcConfig`](crate::types::IdcConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IdcConfigBuilder {
    pub(crate) instance_arn: ::std::option::Option<::std::string::String>,
    pub(crate) application_arn: ::std::option::Option<::std::string::String>,
}
impl IdcConfigBuilder {
    /// <p>The Amazon Resource Name (ARN) of the identity center instance.</p>
    pub fn instance_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the identity center instance.</p>
    pub fn set_instance_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the identity center instance.</p>
    pub fn get_instance_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn set_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the application.</p>
    pub fn get_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_arn
    }
    /// Consumes the builder and constructs a [`IdcConfig`](crate::types::IdcConfig).
    pub fn build(self) -> crate::types::IdcConfig {
        crate::types::IdcConfig {
            instance_arn: self.instance_arn,
            application_arn: self.application_arn,
        }
    }
}
