// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DisassociateNetworkSettingsInput {
    /// <p>The ARN of the web portal.</p>
    pub portal_arn: ::std::option::Option<::std::string::String>,
}
impl DisassociateNetworkSettingsInput {
    /// <p>The ARN of the web portal.</p>
    pub fn portal_arn(&self) -> ::std::option::Option<&str> {
        self.portal_arn.as_deref()
    }
}
impl DisassociateNetworkSettingsInput {
    /// Creates a new builder-style object to manufacture [`DisassociateNetworkSettingsInput`](crate::operation::disassociate_network_settings::DisassociateNetworkSettingsInput).
    pub fn builder() -> crate::operation::disassociate_network_settings::builders::DisassociateNetworkSettingsInputBuilder {
        crate::operation::disassociate_network_settings::builders::DisassociateNetworkSettingsInputBuilder::default()
    }
}

/// A builder for [`DisassociateNetworkSettingsInput`](crate::operation::disassociate_network_settings::DisassociateNetworkSettingsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DisassociateNetworkSettingsInputBuilder {
    pub(crate) portal_arn: ::std::option::Option<::std::string::String>,
}
impl DisassociateNetworkSettingsInputBuilder {
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
    /// Consumes the builder and constructs a [`DisassociateNetworkSettingsInput`](crate::operation::disassociate_network_settings::DisassociateNetworkSettingsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::disassociate_network_settings::DisassociateNetworkSettingsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::disassociate_network_settings::DisassociateNetworkSettingsInput { portal_arn: self.portal_arn })
    }
}
