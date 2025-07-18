// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateDataProtectionSettingsInput {
    /// <p>The ARN of the web portal.</p>
    pub portal_arn: ::std::option::Option<::std::string::String>,
}
impl DisassociateDataProtectionSettingsInput {
    /// <p>The ARN of the web portal.</p>
    pub fn portal_arn(&self) -> ::std::option::Option<&str> {
        self.portal_arn.as_deref()
    }
}
impl DisassociateDataProtectionSettingsInput {
    /// Creates a new builder-style object to manufacture [`DisassociateDataProtectionSettingsInput`](crate::operation::disassociate_data_protection_settings::DisassociateDataProtectionSettingsInput).
    pub fn builder() -> crate::operation::disassociate_data_protection_settings::builders::DisassociateDataProtectionSettingsInputBuilder {
        crate::operation::disassociate_data_protection_settings::builders::DisassociateDataProtectionSettingsInputBuilder::default()
    }
}

/// A builder for [`DisassociateDataProtectionSettingsInput`](crate::operation::disassociate_data_protection_settings::DisassociateDataProtectionSettingsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateDataProtectionSettingsInputBuilder {
    pub(crate) portal_arn: ::std::option::Option<::std::string::String>,
}
impl DisassociateDataProtectionSettingsInputBuilder {
    /// <p>The ARN of the web portal.</p>
    /// This field is required.
    pub fn portal_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.portal_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the web portal.</p>
    pub fn set_portal_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.portal_arn = input;
        self
    }
    /// <p>The ARN of the web portal.</p>
    pub fn get_portal_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.portal_arn
    }
    /// Consumes the builder and constructs a [`DisassociateDataProtectionSettingsInput`](crate::operation::disassociate_data_protection_settings::DisassociateDataProtectionSettingsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_data_protection_settings::DisassociateDataProtectionSettingsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::disassociate_data_protection_settings::DisassociateDataProtectionSettingsInput { portal_arn: self.portal_arn },
        )
    }
}
