// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutEmailMonitoringConfigurationInput {
    /// <p>The ID of the organization for which the email monitoring configuration is set.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the IAM Role associated with the email monitoring configuration.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Log group associated with the email monitoring configuration.</p>
    pub log_group_arn: ::std::option::Option<::std::string::String>,
}
impl PutEmailMonitoringConfigurationInput {
    /// <p>The ID of the organization for which the email monitoring configuration is set.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM Role associated with the email monitoring configuration.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Log group associated with the email monitoring configuration.</p>
    pub fn log_group_arn(&self) -> ::std::option::Option<&str> {
        self.log_group_arn.as_deref()
    }
}
impl PutEmailMonitoringConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutEmailMonitoringConfigurationInput`](crate::operation::put_email_monitoring_configuration::PutEmailMonitoringConfigurationInput).
    pub fn builder() -> crate::operation::put_email_monitoring_configuration::builders::PutEmailMonitoringConfigurationInputBuilder {
        crate::operation::put_email_monitoring_configuration::builders::PutEmailMonitoringConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutEmailMonitoringConfigurationInput`](crate::operation::put_email_monitoring_configuration::PutEmailMonitoringConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutEmailMonitoringConfigurationInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
    pub(crate) log_group_arn: ::std::option::Option<::std::string::String>,
}
impl PutEmailMonitoringConfigurationInputBuilder {
    /// <p>The ID of the organization for which the email monitoring configuration is set.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the organization for which the email monitoring configuration is set.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The ID of the organization for which the email monitoring configuration is set.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM Role associated with the email monitoring configuration.</p>
    /// This field is required.
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM Role associated with the email monitoring configuration.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the IAM Role associated with the email monitoring configuration.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Log group associated with the email monitoring configuration.</p>
    /// This field is required.
    pub fn log_group_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.log_group_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Log group associated with the email monitoring configuration.</p>
    pub fn set_log_group_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.log_group_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the CloudWatch Log group associated with the email monitoring configuration.</p>
    pub fn get_log_group_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.log_group_arn
    }
    /// Consumes the builder and constructs a [`PutEmailMonitoringConfigurationInput`](crate::operation::put_email_monitoring_configuration::PutEmailMonitoringConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_email_monitoring_configuration::PutEmailMonitoringConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_email_monitoring_configuration::PutEmailMonitoringConfigurationInput {
                organization_id: self.organization_id,
                role_arn: self.role_arn,
                log_group_arn: self.log_group_arn,
            },
        )
    }
}
