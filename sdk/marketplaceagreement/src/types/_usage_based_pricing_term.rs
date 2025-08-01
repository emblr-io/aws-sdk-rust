// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a usage-based pricing model (typically, pay-as-you-go pricing), where the customers are charged based on product usage.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UsageBasedPricingTerm {
    /// <p>Category of the term.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
    /// <p>Defines the currency for the prices mentioned in the term.</p>
    pub currency_code: ::std::option::Option<::std::string::String>,
    /// <p>List of rate cards.</p>
    pub rate_cards: ::std::option::Option<::std::vec::Vec<crate::types::UsageBasedRateCardItem>>,
}
impl UsageBasedPricingTerm {
    /// <p>Category of the term.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
    /// <p>Defines the currency for the prices mentioned in the term.</p>
    pub fn currency_code(&self) -> ::std::option::Option<&str> {
        self.currency_code.as_deref()
    }
    /// <p>List of rate cards.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.rate_cards.is_none()`.
    pub fn rate_cards(&self) -> &[crate::types::UsageBasedRateCardItem] {
        self.rate_cards.as_deref().unwrap_or_default()
    }
}
impl UsageBasedPricingTerm {
    /// Creates a new builder-style object to manufacture [`UsageBasedPricingTerm`](crate::types::UsageBasedPricingTerm).
    pub fn builder() -> crate::types::builders::UsageBasedPricingTermBuilder {
        crate::types::builders::UsageBasedPricingTermBuilder::default()
    }
}

/// A builder for [`UsageBasedPricingTerm`](crate::types::UsageBasedPricingTerm).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UsageBasedPricingTermBuilder {
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
    pub(crate) currency_code: ::std::option::Option<::std::string::String>,
    pub(crate) rate_cards: ::std::option::Option<::std::vec::Vec<crate::types::UsageBasedRateCardItem>>,
}
impl UsageBasedPricingTermBuilder {
    /// <p>Category of the term.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Category of the term.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Category of the term.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// <p>Defines the currency for the prices mentioned in the term.</p>
    pub fn currency_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.currency_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Defines the currency for the prices mentioned in the term.</p>
    pub fn set_currency_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.currency_code = input;
        self
    }
    /// <p>Defines the currency for the prices mentioned in the term.</p>
    pub fn get_currency_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.currency_code
    }
    /// Appends an item to `rate_cards`.
    ///
    /// To override the contents of this collection use [`set_rate_cards`](Self::set_rate_cards).
    ///
    /// <p>List of rate cards.</p>
    pub fn rate_cards(mut self, input: crate::types::UsageBasedRateCardItem) -> Self {
        let mut v = self.rate_cards.unwrap_or_default();
        v.push(input);
        self.rate_cards = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of rate cards.</p>
    pub fn set_rate_cards(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::UsageBasedRateCardItem>>) -> Self {
        self.rate_cards = input;
        self
    }
    /// <p>List of rate cards.</p>
    pub fn get_rate_cards(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::UsageBasedRateCardItem>> {
        &self.rate_cards
    }
    /// Consumes the builder and constructs a [`UsageBasedPricingTerm`](crate::types::UsageBasedPricingTerm).
    pub fn build(self) -> crate::types::UsageBasedPricingTerm {
        crate::types::UsageBasedPricingTerm {
            r#type: self.r#type,
            currency_code: self.currency_code,
            rate_cards: self.rate_cards,
        }
    }
}
