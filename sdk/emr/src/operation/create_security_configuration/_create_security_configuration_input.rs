// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSecurityConfigurationInput {
    /// <p>The name of the security configuration.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The security configuration details in JSON format. For JSON parameters and examples, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html">Use Security Configurations to Set Up Cluster Security</a> in the <i>Amazon EMR Management Guide</i>.</p>
    pub security_configuration: ::std::option::Option<::std::string::String>,
}
impl CreateSecurityConfigurationInput {
    /// <p>The name of the security configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The security configuration details in JSON format. For JSON parameters and examples, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html">Use Security Configurations to Set Up Cluster Security</a> in the <i>Amazon EMR Management Guide</i>.</p>
    pub fn security_configuration(&self) -> ::std::option::Option<&str> {
        self.security_configuration.as_deref()
    }
}
impl CreateSecurityConfigurationInput {
    /// Creates a new builder-style object to manufacture [`CreateSecurityConfigurationInput`](crate::operation::create_security_configuration::CreateSecurityConfigurationInput).
    pub fn builder() -> crate::operation::create_security_configuration::builders::CreateSecurityConfigurationInputBuilder {
        crate::operation::create_security_configuration::builders::CreateSecurityConfigurationInputBuilder::default()
    }
}

/// A builder for [`CreateSecurityConfigurationInput`](crate::operation::create_security_configuration::CreateSecurityConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSecurityConfigurationInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) security_configuration: ::std::option::Option<::std::string::String>,
}
impl CreateSecurityConfigurationInputBuilder {
    /// <p>The name of the security configuration.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the security configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the security configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The security configuration details in JSON format. For JSON parameters and examples, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html">Use Security Configurations to Set Up Cluster Security</a> in the <i>Amazon EMR Management Guide</i>.</p>
    /// This field is required.
    pub fn security_configuration(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.security_configuration = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The security configuration details in JSON format. For JSON parameters and examples, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html">Use Security Configurations to Set Up Cluster Security</a> in the <i>Amazon EMR Management Guide</i>.</p>
    pub fn set_security_configuration(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.security_configuration = input;
        self
    }
    /// <p>The security configuration details in JSON format. For JSON parameters and examples, see <a href="https://docs.aws.amazon.com/emr/latest/ManagementGuide/emr-security-configurations.html">Use Security Configurations to Set Up Cluster Security</a> in the <i>Amazon EMR Management Guide</i>.</p>
    pub fn get_security_configuration(&self) -> &::std::option::Option<::std::string::String> {
        &self.security_configuration
    }
    /// Consumes the builder and constructs a [`CreateSecurityConfigurationInput`](crate::operation::create_security_configuration::CreateSecurityConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_security_configuration::CreateSecurityConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_security_configuration::CreateSecurityConfigurationInput {
            name: self.name,
            security_configuration: self.security_configuration,
        })
    }
}
