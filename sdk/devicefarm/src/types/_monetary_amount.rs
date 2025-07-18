// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A number that represents the monetary amount for an offering or transaction.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MonetaryAmount {
    /// <p>The numerical amount of an offering or transaction.</p>
    pub amount: ::std::option::Option<f64>,
    /// <p>The currency code of a monetary amount. For example, <code>USD</code> means U.S. dollars.</p>
    pub currency_code: ::std::option::Option<crate::types::CurrencyCode>,
}
impl MonetaryAmount {
    /// <p>The numerical amount of an offering or transaction.</p>
    pub fn amount(&self) -> ::std::option::Option<f64> {
        self.amount
    }
    /// <p>The currency code of a monetary amount. For example, <code>USD</code> means U.S. dollars.</p>
    pub fn currency_code(&self) -> ::std::option::Option<&crate::types::CurrencyCode> {
        self.currency_code.as_ref()
    }
}
impl MonetaryAmount {
    /// Creates a new builder-style object to manufacture [`MonetaryAmount`](crate::types::MonetaryAmount).
    pub fn builder() -> crate::types::builders::MonetaryAmountBuilder {
        crate::types::builders::MonetaryAmountBuilder::default()
    }
}

/// A builder for [`MonetaryAmount`](crate::types::MonetaryAmount).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MonetaryAmountBuilder {
    pub(crate) amount: ::std::option::Option<f64>,
    pub(crate) currency_code: ::std::option::Option<crate::types::CurrencyCode>,
}
impl MonetaryAmountBuilder {
    /// <p>The numerical amount of an offering or transaction.</p>
    pub fn amount(mut self, input: f64) -> Self {
        self.amount = ::std::option::Option::Some(input);
        self
    }
    /// <p>The numerical amount of an offering or transaction.</p>
    pub fn set_amount(mut self, input: ::std::option::Option<f64>) -> Self {
        self.amount = input;
        self
    }
    /// <p>The numerical amount of an offering or transaction.</p>
    pub fn get_amount(&self) -> &::std::option::Option<f64> {
        &self.amount
    }
    /// <p>The currency code of a monetary amount. For example, <code>USD</code> means U.S. dollars.</p>
    pub fn currency_code(mut self, input: crate::types::CurrencyCode) -> Self {
        self.currency_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The currency code of a monetary amount. For example, <code>USD</code> means U.S. dollars.</p>
    pub fn set_currency_code(mut self, input: ::std::option::Option<crate::types::CurrencyCode>) -> Self {
        self.currency_code = input;
        self
    }
    /// <p>The currency code of a monetary amount. For example, <code>USD</code> means U.S. dollars.</p>
    pub fn get_currency_code(&self) -> &::std::option::Option<crate::types::CurrencyCode> {
        &self.currency_code
    }
    /// Consumes the builder and constructs a [`MonetaryAmount`](crate::types::MonetaryAmount).
    pub fn build(self) -> crate::types::MonetaryAmount {
        crate::types::MonetaryAmount {
            amount: self.amount,
            currency_code: self.currency_code,
        }
    }
}
