// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the taxes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaxesBreakdown {
    /// <p>A list of tax information.</p>
    pub breakdown: ::std::option::Option<::std::vec::Vec<crate::types::TaxesBreakdownAmount>>,
    /// <p>The total amount for your taxes.</p>
    pub total_amount: ::std::option::Option<::std::string::String>,
}
impl TaxesBreakdown {
    /// <p>A list of tax information.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.breakdown.is_none()`.
    pub fn breakdown(&self) -> &[crate::types::TaxesBreakdownAmount] {
        self.breakdown.as_deref().unwrap_or_default()
    }
    /// <p>The total amount for your taxes.</p>
    pub fn total_amount(&self) -> ::std::option::Option<&str> {
        self.total_amount.as_deref()
    }
}
impl TaxesBreakdown {
    /// Creates a new builder-style object to manufacture [`TaxesBreakdown`](crate::types::TaxesBreakdown).
    pub fn builder() -> crate::types::builders::TaxesBreakdownBuilder {
        crate::types::builders::TaxesBreakdownBuilder::default()
    }
}

/// A builder for [`TaxesBreakdown`](crate::types::TaxesBreakdown).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaxesBreakdownBuilder {
    pub(crate) breakdown: ::std::option::Option<::std::vec::Vec<crate::types::TaxesBreakdownAmount>>,
    pub(crate) total_amount: ::std::option::Option<::std::string::String>,
}
impl TaxesBreakdownBuilder {
    /// Appends an item to `breakdown`.
    ///
    /// To override the contents of this collection use [`set_breakdown`](Self::set_breakdown).
    ///
    /// <p>A list of tax information.</p>
    pub fn breakdown(mut self, input: crate::types::TaxesBreakdownAmount) -> Self {
        let mut v = self.breakdown.unwrap_or_default();
        v.push(input);
        self.breakdown = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tax information.</p>
    pub fn set_breakdown(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TaxesBreakdownAmount>>) -> Self {
        self.breakdown = input;
        self
    }
    /// <p>A list of tax information.</p>
    pub fn get_breakdown(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TaxesBreakdownAmount>> {
        &self.breakdown
    }
    /// <p>The total amount for your taxes.</p>
    pub fn total_amount(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.total_amount = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The total amount for your taxes.</p>
    pub fn set_total_amount(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.total_amount = input;
        self
    }
    /// <p>The total amount for your taxes.</p>
    pub fn get_total_amount(&self) -> &::std::option::Option<::std::string::String> {
        &self.total_amount
    }
    /// Consumes the builder and constructs a [`TaxesBreakdown`](crate::types::TaxesBreakdown).
    pub fn build(self) -> crate::types::TaxesBreakdown {
        crate::types::TaxesBreakdown {
            breakdown: self.breakdown,
            total_amount: self.total_amount,
        }
    }
}
