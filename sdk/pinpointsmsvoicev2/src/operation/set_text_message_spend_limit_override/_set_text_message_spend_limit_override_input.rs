// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SetTextMessageSpendLimitOverrideInput {
    /// <p>The new monthly limit to enforce on text messages.</p>
    pub monthly_limit: ::std::option::Option<i64>,
}
impl SetTextMessageSpendLimitOverrideInput {
    /// <p>The new monthly limit to enforce on text messages.</p>
    pub fn monthly_limit(&self) -> ::std::option::Option<i64> {
        self.monthly_limit
    }
}
impl SetTextMessageSpendLimitOverrideInput {
    /// Creates a new builder-style object to manufacture [`SetTextMessageSpendLimitOverrideInput`](crate::operation::set_text_message_spend_limit_override::SetTextMessageSpendLimitOverrideInput).
    pub fn builder() -> crate::operation::set_text_message_spend_limit_override::builders::SetTextMessageSpendLimitOverrideInputBuilder {
        crate::operation::set_text_message_spend_limit_override::builders::SetTextMessageSpendLimitOverrideInputBuilder::default()
    }
}

/// A builder for [`SetTextMessageSpendLimitOverrideInput`](crate::operation::set_text_message_spend_limit_override::SetTextMessageSpendLimitOverrideInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SetTextMessageSpendLimitOverrideInputBuilder {
    pub(crate) monthly_limit: ::std::option::Option<i64>,
}
impl SetTextMessageSpendLimitOverrideInputBuilder {
    /// <p>The new monthly limit to enforce on text messages.</p>
    /// This field is required.
    pub fn monthly_limit(mut self, input: i64) -> Self {
        self.monthly_limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The new monthly limit to enforce on text messages.</p>
    pub fn set_monthly_limit(mut self, input: ::std::option::Option<i64>) -> Self {
        self.monthly_limit = input;
        self
    }
    /// <p>The new monthly limit to enforce on text messages.</p>
    pub fn get_monthly_limit(&self) -> &::std::option::Option<i64> {
        &self.monthly_limit
    }
    /// Consumes the builder and constructs a [`SetTextMessageSpendLimitOverrideInput`](crate::operation::set_text_message_spend_limit_override::SetTextMessageSpendLimitOverrideInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::set_text_message_spend_limit_override::SetTextMessageSpendLimitOverrideInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::set_text_message_spend_limit_override::SetTextMessageSpendLimitOverrideInput {
                monthly_limit: self.monthly_limit,
            },
        )
    }
}
