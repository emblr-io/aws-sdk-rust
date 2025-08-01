// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the usage terms of an offer.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TermDetails {
    /// <p>Describes the usage-based pricing term.</p>
    pub usage_based_pricing_term: ::std::option::Option<crate::types::PricingTerm>,
    /// <p>Describes the legal terms.</p>
    pub legal_term: ::std::option::Option<crate::types::LegalTerm>,
    /// <p>Describes the support terms.</p>
    pub support_term: ::std::option::Option<crate::types::SupportTerm>,
    /// <p>Describes the validity terms.</p>
    pub validity_term: ::std::option::Option<crate::types::ValidityTerm>,
}
impl TermDetails {
    /// <p>Describes the usage-based pricing term.</p>
    pub fn usage_based_pricing_term(&self) -> ::std::option::Option<&crate::types::PricingTerm> {
        self.usage_based_pricing_term.as_ref()
    }
    /// <p>Describes the legal terms.</p>
    pub fn legal_term(&self) -> ::std::option::Option<&crate::types::LegalTerm> {
        self.legal_term.as_ref()
    }
    /// <p>Describes the support terms.</p>
    pub fn support_term(&self) -> ::std::option::Option<&crate::types::SupportTerm> {
        self.support_term.as_ref()
    }
    /// <p>Describes the validity terms.</p>
    pub fn validity_term(&self) -> ::std::option::Option<&crate::types::ValidityTerm> {
        self.validity_term.as_ref()
    }
}
impl TermDetails {
    /// Creates a new builder-style object to manufacture [`TermDetails`](crate::types::TermDetails).
    pub fn builder() -> crate::types::builders::TermDetailsBuilder {
        crate::types::builders::TermDetailsBuilder::default()
    }
}

/// A builder for [`TermDetails`](crate::types::TermDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TermDetailsBuilder {
    pub(crate) usage_based_pricing_term: ::std::option::Option<crate::types::PricingTerm>,
    pub(crate) legal_term: ::std::option::Option<crate::types::LegalTerm>,
    pub(crate) support_term: ::std::option::Option<crate::types::SupportTerm>,
    pub(crate) validity_term: ::std::option::Option<crate::types::ValidityTerm>,
}
impl TermDetailsBuilder {
    /// <p>Describes the usage-based pricing term.</p>
    /// This field is required.
    pub fn usage_based_pricing_term(mut self, input: crate::types::PricingTerm) -> Self {
        self.usage_based_pricing_term = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the usage-based pricing term.</p>
    pub fn set_usage_based_pricing_term(mut self, input: ::std::option::Option<crate::types::PricingTerm>) -> Self {
        self.usage_based_pricing_term = input;
        self
    }
    /// <p>Describes the usage-based pricing term.</p>
    pub fn get_usage_based_pricing_term(&self) -> &::std::option::Option<crate::types::PricingTerm> {
        &self.usage_based_pricing_term
    }
    /// <p>Describes the legal terms.</p>
    /// This field is required.
    pub fn legal_term(mut self, input: crate::types::LegalTerm) -> Self {
        self.legal_term = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the legal terms.</p>
    pub fn set_legal_term(mut self, input: ::std::option::Option<crate::types::LegalTerm>) -> Self {
        self.legal_term = input;
        self
    }
    /// <p>Describes the legal terms.</p>
    pub fn get_legal_term(&self) -> &::std::option::Option<crate::types::LegalTerm> {
        &self.legal_term
    }
    /// <p>Describes the support terms.</p>
    /// This field is required.
    pub fn support_term(mut self, input: crate::types::SupportTerm) -> Self {
        self.support_term = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the support terms.</p>
    pub fn set_support_term(mut self, input: ::std::option::Option<crate::types::SupportTerm>) -> Self {
        self.support_term = input;
        self
    }
    /// <p>Describes the support terms.</p>
    pub fn get_support_term(&self) -> &::std::option::Option<crate::types::SupportTerm> {
        &self.support_term
    }
    /// <p>Describes the validity terms.</p>
    pub fn validity_term(mut self, input: crate::types::ValidityTerm) -> Self {
        self.validity_term = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the validity terms.</p>
    pub fn set_validity_term(mut self, input: ::std::option::Option<crate::types::ValidityTerm>) -> Self {
        self.validity_term = input;
        self
    }
    /// <p>Describes the validity terms.</p>
    pub fn get_validity_term(&self) -> &::std::option::Option<crate::types::ValidityTerm> {
        &self.validity_term
    }
    /// Consumes the builder and constructs a [`TermDetails`](crate::types::TermDetails).
    pub fn build(self) -> crate::types::TermDetails {
        crate::types::TermDetails {
            usage_based_pricing_term: self.usage_based_pricing_term,
            legal_term: self.legal_term,
            support_term: self.support_term,
            validity_term: self.validity_term,
        }
    }
}
