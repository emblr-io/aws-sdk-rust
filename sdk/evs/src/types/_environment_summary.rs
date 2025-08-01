// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A list of environments with summarized environment details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnvironmentSummary {
    /// <p>A unique ID for the environment.</p>
    pub environment_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the environment.</p>
    pub environment_name: ::std::option::Option<::std::string::String>,
    /// <p>The VCF version of the environment.</p>
    pub vcf_version: ::std::option::Option<crate::types::VcfVersion>,
    /// <p>Reports impaired functionality that stems from issues internal to the environment, such as impaired reachability.</p>
    pub environment_status: ::std::option::Option<crate::types::CheckResult>,
    /// <p>The state of an environment.</p>
    pub environment_state: ::std::option::Option<crate::types::EnvironmentState>,
    /// <p>The date and time that the environment was created.</p>
    pub created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The date and time that the environment was modified.</p>
    pub modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The Amazon Resource Name (ARN) that is associated with the environment.</p>
    pub environment_arn: ::std::option::Option<::std::string::String>,
}
impl EnvironmentSummary {
    /// <p>A unique ID for the environment.</p>
    pub fn environment_id(&self) -> ::std::option::Option<&str> {
        self.environment_id.as_deref()
    }
    /// <p>The name of the environment.</p>
    pub fn environment_name(&self) -> ::std::option::Option<&str> {
        self.environment_name.as_deref()
    }
    /// <p>The VCF version of the environment.</p>
    pub fn vcf_version(&self) -> ::std::option::Option<&crate::types::VcfVersion> {
        self.vcf_version.as_ref()
    }
    /// <p>Reports impaired functionality that stems from issues internal to the environment, such as impaired reachability.</p>
    pub fn environment_status(&self) -> ::std::option::Option<&crate::types::CheckResult> {
        self.environment_status.as_ref()
    }
    /// <p>The state of an environment.</p>
    pub fn environment_state(&self) -> ::std::option::Option<&crate::types::EnvironmentState> {
        self.environment_state.as_ref()
    }
    /// <p>The date and time that the environment was created.</p>
    pub fn created_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.created_at.as_ref()
    }
    /// <p>The date and time that the environment was modified.</p>
    pub fn modified_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.modified_at.as_ref()
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the environment.</p>
    pub fn environment_arn(&self) -> ::std::option::Option<&str> {
        self.environment_arn.as_deref()
    }
}
impl EnvironmentSummary {
    /// Creates a new builder-style object to manufacture [`EnvironmentSummary`](crate::types::EnvironmentSummary).
    pub fn builder() -> crate::types::builders::EnvironmentSummaryBuilder {
        crate::types::builders::EnvironmentSummaryBuilder::default()
    }
}

/// A builder for [`EnvironmentSummary`](crate::types::EnvironmentSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnvironmentSummaryBuilder {
    pub(crate) environment_id: ::std::option::Option<::std::string::String>,
    pub(crate) environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) vcf_version: ::std::option::Option<crate::types::VcfVersion>,
    pub(crate) environment_status: ::std::option::Option<crate::types::CheckResult>,
    pub(crate) environment_state: ::std::option::Option<crate::types::EnvironmentState>,
    pub(crate) created_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) modified_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) environment_arn: ::std::option::Option<::std::string::String>,
}
impl EnvironmentSummaryBuilder {
    /// <p>A unique ID for the environment.</p>
    pub fn environment_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique ID for the environment.</p>
    pub fn set_environment_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_id = input;
        self
    }
    /// <p>A unique ID for the environment.</p>
    pub fn get_environment_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_id
    }
    /// <p>The name of the environment.</p>
    pub fn environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the environment.</p>
    pub fn set_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_name = input;
        self
    }
    /// <p>The name of the environment.</p>
    pub fn get_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_name
    }
    /// <p>The VCF version of the environment.</p>
    pub fn vcf_version(mut self, input: crate::types::VcfVersion) -> Self {
        self.vcf_version = ::std::option::Option::Some(input);
        self
    }
    /// <p>The VCF version of the environment.</p>
    pub fn set_vcf_version(mut self, input: ::std::option::Option<crate::types::VcfVersion>) -> Self {
        self.vcf_version = input;
        self
    }
    /// <p>The VCF version of the environment.</p>
    pub fn get_vcf_version(&self) -> &::std::option::Option<crate::types::VcfVersion> {
        &self.vcf_version
    }
    /// <p>Reports impaired functionality that stems from issues internal to the environment, such as impaired reachability.</p>
    pub fn environment_status(mut self, input: crate::types::CheckResult) -> Self {
        self.environment_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Reports impaired functionality that stems from issues internal to the environment, such as impaired reachability.</p>
    pub fn set_environment_status(mut self, input: ::std::option::Option<crate::types::CheckResult>) -> Self {
        self.environment_status = input;
        self
    }
    /// <p>Reports impaired functionality that stems from issues internal to the environment, such as impaired reachability.</p>
    pub fn get_environment_status(&self) -> &::std::option::Option<crate::types::CheckResult> {
        &self.environment_status
    }
    /// <p>The state of an environment.</p>
    pub fn environment_state(mut self, input: crate::types::EnvironmentState) -> Self {
        self.environment_state = ::std::option::Option::Some(input);
        self
    }
    /// <p>The state of an environment.</p>
    pub fn set_environment_state(mut self, input: ::std::option::Option<crate::types::EnvironmentState>) -> Self {
        self.environment_state = input;
        self
    }
    /// <p>The state of an environment.</p>
    pub fn get_environment_state(&self) -> &::std::option::Option<crate::types::EnvironmentState> {
        &self.environment_state
    }
    /// <p>The date and time that the environment was created.</p>
    pub fn created_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.created_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the environment was created.</p>
    pub fn set_created_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.created_at = input;
        self
    }
    /// <p>The date and time that the environment was created.</p>
    pub fn get_created_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.created_at
    }
    /// <p>The date and time that the environment was modified.</p>
    pub fn modified_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.modified_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time that the environment was modified.</p>
    pub fn set_modified_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.modified_at = input;
        self
    }
    /// <p>The date and time that the environment was modified.</p>
    pub fn get_modified_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.modified_at
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the environment.</p>
    pub fn environment_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.environment_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the environment.</p>
    pub fn set_environment_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.environment_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that is associated with the environment.</p>
    pub fn get_environment_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.environment_arn
    }
    /// Consumes the builder and constructs a [`EnvironmentSummary`](crate::types::EnvironmentSummary).
    pub fn build(self) -> crate::types::EnvironmentSummary {
        crate::types::EnvironmentSummary {
            environment_id: self.environment_id,
            environment_name: self.environment_name,
            vcf_version: self.vcf_version,
            environment_status: self.environment_status,
            environment_state: self.environment_state,
            created_at: self.created_at,
            modified_at: self.modified_at,
            environment_arn: self.environment_arn,
        }
    }
}
