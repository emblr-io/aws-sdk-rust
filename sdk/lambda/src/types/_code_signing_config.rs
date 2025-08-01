// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about a <a href="https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html">Code signing configuration</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodeSigningConfig {
    /// <p>Unique identifer for the Code signing configuration.</p>
    pub code_signing_config_id: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the Code signing configuration.</p>
    pub code_signing_config_arn: ::std::string::String,
    /// <p>Code signing configuration description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>List of allowed publishers.</p>
    pub allowed_publishers: ::std::option::Option<crate::types::AllowedPublishers>,
    /// <p>The code signing policy controls the validation failure action for signature mismatch or expiry.</p>
    pub code_signing_policies: ::std::option::Option<crate::types::CodeSigningPolicies>,
    /// <p>The date and time that the Code signing configuration was last modified, in ISO-8601 format (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub last_modified: ::std::string::String,
}
impl CodeSigningConfig {
    /// <p>Unique identifer for the Code signing configuration.</p>
    pub fn code_signing_config_id(&self) -> &str {
        use std::ops::Deref;
        self.code_signing_config_id.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the Code signing configuration.</p>
    pub fn code_signing_config_arn(&self) -> &str {
        use std::ops::Deref;
        self.code_signing_config_arn.deref()
    }
    /// <p>Code signing configuration description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>List of allowed publishers.</p>
    pub fn allowed_publishers(&self) -> ::std::option::Option<&crate::types::AllowedPublishers> {
        self.allowed_publishers.as_ref()
    }
    /// <p>The code signing policy controls the validation failure action for signature mismatch or expiry.</p>
    pub fn code_signing_policies(&self) -> ::std::option::Option<&crate::types::CodeSigningPolicies> {
        self.code_signing_policies.as_ref()
    }
    /// <p>The date and time that the Code signing configuration was last modified, in ISO-8601 format (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn last_modified(&self) -> &str {
        use std::ops::Deref;
        self.last_modified.deref()
    }
}
impl CodeSigningConfig {
    /// Creates a new builder-style object to manufacture [`CodeSigningConfig`](crate::types::CodeSigningConfig).
    pub fn builder() -> crate::types::builders::CodeSigningConfigBuilder {
        crate::types::builders::CodeSigningConfigBuilder::default()
    }
}

/// A builder for [`CodeSigningConfig`](crate::types::CodeSigningConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodeSigningConfigBuilder {
    pub(crate) code_signing_config_id: ::std::option::Option<::std::string::String>,
    pub(crate) code_signing_config_arn: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) allowed_publishers: ::std::option::Option<crate::types::AllowedPublishers>,
    pub(crate) code_signing_policies: ::std::option::Option<crate::types::CodeSigningPolicies>,
    pub(crate) last_modified: ::std::option::Option<::std::string::String>,
}
impl CodeSigningConfigBuilder {
    /// <p>Unique identifer for the Code signing configuration.</p>
    /// This field is required.
    pub fn code_signing_config_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code_signing_config_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique identifer for the Code signing configuration.</p>
    pub fn set_code_signing_config_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code_signing_config_id = input;
        self
    }
    /// <p>Unique identifer for the Code signing configuration.</p>
    pub fn get_code_signing_config_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.code_signing_config_id
    }
    /// <p>The Amazon Resource Name (ARN) of the Code signing configuration.</p>
    /// This field is required.
    pub fn code_signing_config_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.code_signing_config_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Code signing configuration.</p>
    pub fn set_code_signing_config_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.code_signing_config_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the Code signing configuration.</p>
    pub fn get_code_signing_config_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.code_signing_config_arn
    }
    /// <p>Code signing configuration description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Code signing configuration description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Code signing configuration description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>List of allowed publishers.</p>
    /// This field is required.
    pub fn allowed_publishers(mut self, input: crate::types::AllowedPublishers) -> Self {
        self.allowed_publishers = ::std::option::Option::Some(input);
        self
    }
    /// <p>List of allowed publishers.</p>
    pub fn set_allowed_publishers(mut self, input: ::std::option::Option<crate::types::AllowedPublishers>) -> Self {
        self.allowed_publishers = input;
        self
    }
    /// <p>List of allowed publishers.</p>
    pub fn get_allowed_publishers(&self) -> &::std::option::Option<crate::types::AllowedPublishers> {
        &self.allowed_publishers
    }
    /// <p>The code signing policy controls the validation failure action for signature mismatch or expiry.</p>
    /// This field is required.
    pub fn code_signing_policies(mut self, input: crate::types::CodeSigningPolicies) -> Self {
        self.code_signing_policies = ::std::option::Option::Some(input);
        self
    }
    /// <p>The code signing policy controls the validation failure action for signature mismatch or expiry.</p>
    pub fn set_code_signing_policies(mut self, input: ::std::option::Option<crate::types::CodeSigningPolicies>) -> Self {
        self.code_signing_policies = input;
        self
    }
    /// <p>The code signing policy controls the validation failure action for signature mismatch or expiry.</p>
    pub fn get_code_signing_policies(&self) -> &::std::option::Option<crate::types::CodeSigningPolicies> {
        &self.code_signing_policies
    }
    /// <p>The date and time that the Code signing configuration was last modified, in ISO-8601 format (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    /// This field is required.
    pub fn last_modified(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_modified = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The date and time that the Code signing configuration was last modified, in ISO-8601 format (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn set_last_modified(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_modified = input;
        self
    }
    /// <p>The date and time that the Code signing configuration was last modified, in ISO-8601 format (YYYY-MM-DDThh:mm:ss.sTZD).</p>
    pub fn get_last_modified(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_modified
    }
    /// Consumes the builder and constructs a [`CodeSigningConfig`](crate::types::CodeSigningConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`code_signing_config_id`](crate::types::builders::CodeSigningConfigBuilder::code_signing_config_id)
    /// - [`code_signing_config_arn`](crate::types::builders::CodeSigningConfigBuilder::code_signing_config_arn)
    /// - [`last_modified`](crate::types::builders::CodeSigningConfigBuilder::last_modified)
    pub fn build(self) -> ::std::result::Result<crate::types::CodeSigningConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CodeSigningConfig {
            code_signing_config_id: self.code_signing_config_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "code_signing_config_id",
                    "code_signing_config_id was not specified but it is required when building CodeSigningConfig",
                )
            })?,
            code_signing_config_arn: self.code_signing_config_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "code_signing_config_arn",
                    "code_signing_config_arn was not specified but it is required when building CodeSigningConfig",
                )
            })?,
            description: self.description,
            allowed_publishers: self.allowed_publishers,
            code_signing_policies: self.code_signing_policies,
            last_modified: self.last_modified.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_modified",
                    "last_modified was not specified but it is required when building CodeSigningConfig",
                )
            })?,
        })
    }
}
