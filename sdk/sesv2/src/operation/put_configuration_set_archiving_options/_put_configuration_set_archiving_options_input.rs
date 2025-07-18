// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to associate a configuration set with a MailManager archive.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutConfigurationSetArchivingOptionsInput {
    /// <p>The name of the configuration set to associate with a MailManager archive.</p>
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the MailManager archive that the Amazon SES API v2 sends email to.</p>
    pub archive_arn: ::std::option::Option<::std::string::String>,
}
impl PutConfigurationSetArchivingOptionsInput {
    /// <p>The name of the configuration set to associate with a MailManager archive.</p>
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the MailManager archive that the Amazon SES API v2 sends email to.</p>
    pub fn archive_arn(&self) -> ::std::option::Option<&str> {
        self.archive_arn.as_deref()
    }
}
impl PutConfigurationSetArchivingOptionsInput {
    /// Creates a new builder-style object to manufacture [`PutConfigurationSetArchivingOptionsInput`](crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsInput).
    pub fn builder() -> crate::operation::put_configuration_set_archiving_options::builders::PutConfigurationSetArchivingOptionsInputBuilder {
        crate::operation::put_configuration_set_archiving_options::builders::PutConfigurationSetArchivingOptionsInputBuilder::default()
    }
}

/// A builder for [`PutConfigurationSetArchivingOptionsInput`](crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutConfigurationSetArchivingOptionsInputBuilder {
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) archive_arn: ::std::option::Option<::std::string::String>,
}
impl PutConfigurationSetArchivingOptionsInputBuilder {
    /// <p>The name of the configuration set to associate with a MailManager archive.</p>
    /// This field is required.
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration set to associate with a MailManager archive.</p>
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// <p>The name of the configuration set to associate with a MailManager archive.</p>
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
    }
    /// <p>The Amazon Resource Name (ARN) of the MailManager archive that the Amazon SES API v2 sends email to.</p>
    pub fn archive_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.archive_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the MailManager archive that the Amazon SES API v2 sends email to.</p>
    pub fn set_archive_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.archive_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the MailManager archive that the Amazon SES API v2 sends email to.</p>
    pub fn get_archive_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.archive_arn
    }
    /// Consumes the builder and constructs a [`PutConfigurationSetArchivingOptionsInput`](crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_configuration_set_archiving_options::PutConfigurationSetArchivingOptionsInput {
                configuration_set_name: self.configuration_set_name,
                archive_arn: self.archive_arn,
            },
        )
    }
}
