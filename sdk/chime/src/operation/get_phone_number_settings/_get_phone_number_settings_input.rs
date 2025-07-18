// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPhoneNumberSettingsInput {}
impl GetPhoneNumberSettingsInput {
    /// Creates a new builder-style object to manufacture [`GetPhoneNumberSettingsInput`](crate::operation::get_phone_number_settings::GetPhoneNumberSettingsInput).
    pub fn builder() -> crate::operation::get_phone_number_settings::builders::GetPhoneNumberSettingsInputBuilder {
        crate::operation::get_phone_number_settings::builders::GetPhoneNumberSettingsInputBuilder::default()
    }
}

/// A builder for [`GetPhoneNumberSettingsInput`](crate::operation::get_phone_number_settings::GetPhoneNumberSettingsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPhoneNumberSettingsInputBuilder {}
impl GetPhoneNumberSettingsInputBuilder {
    /// Consumes the builder and constructs a [`GetPhoneNumberSettingsInput`](crate::operation::get_phone_number_settings::GetPhoneNumberSettingsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_phone_number_settings::GetPhoneNumberSettingsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::get_phone_number_settings::GetPhoneNumberSettingsInput {})
    }
}
