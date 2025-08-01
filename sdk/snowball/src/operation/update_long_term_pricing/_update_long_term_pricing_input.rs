// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLongTermPricingInput {
    /// <p>The ID of the long-term pricing type for the device.</p>
    pub long_term_pricing_id: ::std::option::Option<::std::string::String>,
    /// <p>Specifies that a device that is ordered with long-term pricing should be replaced with a new device.</p>
    pub replacement_job: ::std::option::Option<::std::string::String>,
    /// <p>If set to <code>true</code>, specifies that the current long-term pricing type for the device should be automatically renewed before the long-term pricing contract expires.</p>
    pub is_long_term_pricing_auto_renew: ::std::option::Option<bool>,
}
impl UpdateLongTermPricingInput {
    /// <p>The ID of the long-term pricing type for the device.</p>
    pub fn long_term_pricing_id(&self) -> ::std::option::Option<&str> {
        self.long_term_pricing_id.as_deref()
    }
    /// <p>Specifies that a device that is ordered with long-term pricing should be replaced with a new device.</p>
    pub fn replacement_job(&self) -> ::std::option::Option<&str> {
        self.replacement_job.as_deref()
    }
    /// <p>If set to <code>true</code>, specifies that the current long-term pricing type for the device should be automatically renewed before the long-term pricing contract expires.</p>
    pub fn is_long_term_pricing_auto_renew(&self) -> ::std::option::Option<bool> {
        self.is_long_term_pricing_auto_renew
    }
}
impl UpdateLongTermPricingInput {
    /// Creates a new builder-style object to manufacture [`UpdateLongTermPricingInput`](crate::operation::update_long_term_pricing::UpdateLongTermPricingInput).
    pub fn builder() -> crate::operation::update_long_term_pricing::builders::UpdateLongTermPricingInputBuilder {
        crate::operation::update_long_term_pricing::builders::UpdateLongTermPricingInputBuilder::default()
    }
}

/// A builder for [`UpdateLongTermPricingInput`](crate::operation::update_long_term_pricing::UpdateLongTermPricingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLongTermPricingInputBuilder {
    pub(crate) long_term_pricing_id: ::std::option::Option<::std::string::String>,
    pub(crate) replacement_job: ::std::option::Option<::std::string::String>,
    pub(crate) is_long_term_pricing_auto_renew: ::std::option::Option<bool>,
}
impl UpdateLongTermPricingInputBuilder {
    /// <p>The ID of the long-term pricing type for the device.</p>
    /// This field is required.
    pub fn long_term_pricing_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.long_term_pricing_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the long-term pricing type for the device.</p>
    pub fn set_long_term_pricing_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.long_term_pricing_id = input;
        self
    }
    /// <p>The ID of the long-term pricing type for the device.</p>
    pub fn get_long_term_pricing_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.long_term_pricing_id
    }
    /// <p>Specifies that a device that is ordered with long-term pricing should be replaced with a new device.</p>
    pub fn replacement_job(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.replacement_job = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies that a device that is ordered with long-term pricing should be replaced with a new device.</p>
    pub fn set_replacement_job(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.replacement_job = input;
        self
    }
    /// <p>Specifies that a device that is ordered with long-term pricing should be replaced with a new device.</p>
    pub fn get_replacement_job(&self) -> &::std::option::Option<::std::string::String> {
        &self.replacement_job
    }
    /// <p>If set to <code>true</code>, specifies that the current long-term pricing type for the device should be automatically renewed before the long-term pricing contract expires.</p>
    pub fn is_long_term_pricing_auto_renew(mut self, input: bool) -> Self {
        self.is_long_term_pricing_auto_renew = ::std::option::Option::Some(input);
        self
    }
    /// <p>If set to <code>true</code>, specifies that the current long-term pricing type for the device should be automatically renewed before the long-term pricing contract expires.</p>
    pub fn set_is_long_term_pricing_auto_renew(mut self, input: ::std::option::Option<bool>) -> Self {
        self.is_long_term_pricing_auto_renew = input;
        self
    }
    /// <p>If set to <code>true</code>, specifies that the current long-term pricing type for the device should be automatically renewed before the long-term pricing contract expires.</p>
    pub fn get_is_long_term_pricing_auto_renew(&self) -> &::std::option::Option<bool> {
        &self.is_long_term_pricing_auto_renew
    }
    /// Consumes the builder and constructs a [`UpdateLongTermPricingInput`](crate::operation::update_long_term_pricing::UpdateLongTermPricingInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_long_term_pricing::UpdateLongTermPricingInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::update_long_term_pricing::UpdateLongTermPricingInput {
            long_term_pricing_id: self.long_term_pricing_id,
            replacement_job: self.replacement_job,
            is_long_term_pricing_auto_renew: self.is_long_term_pricing_auto_renew,
        })
    }
}
