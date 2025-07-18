// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The tax exemption details.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TaxExemptionDetails {
    /// <p>Tax exemptions.</p>
    pub tax_exemptions: ::std::option::Option<::std::vec::Vec<crate::types::TaxExemption>>,
    /// <p>The indicator if the tax exemption is inherited from the consolidated billing family management account.</p>
    pub heritage_obtained_details: ::std::option::Option<bool>,
    /// <p>The consolidated billing family management account the tax exemption inherited from.</p>
    pub heritage_obtained_parent_entity: ::std::option::Option<::std::string::String>,
    /// <p>The reason of the heritage inheritance.</p>
    pub heritage_obtained_reason: ::std::option::Option<::std::string::String>,
}
impl TaxExemptionDetails {
    /// <p>Tax exemptions.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tax_exemptions.is_none()`.
    pub fn tax_exemptions(&self) -> &[crate::types::TaxExemption] {
        self.tax_exemptions.as_deref().unwrap_or_default()
    }
    /// <p>The indicator if the tax exemption is inherited from the consolidated billing family management account.</p>
    pub fn heritage_obtained_details(&self) -> ::std::option::Option<bool> {
        self.heritage_obtained_details
    }
    /// <p>The consolidated billing family management account the tax exemption inherited from.</p>
    pub fn heritage_obtained_parent_entity(&self) -> ::std::option::Option<&str> {
        self.heritage_obtained_parent_entity.as_deref()
    }
    /// <p>The reason of the heritage inheritance.</p>
    pub fn heritage_obtained_reason(&self) -> ::std::option::Option<&str> {
        self.heritage_obtained_reason.as_deref()
    }
}
impl TaxExemptionDetails {
    /// Creates a new builder-style object to manufacture [`TaxExemptionDetails`](crate::types::TaxExemptionDetails).
    pub fn builder() -> crate::types::builders::TaxExemptionDetailsBuilder {
        crate::types::builders::TaxExemptionDetailsBuilder::default()
    }
}

/// A builder for [`TaxExemptionDetails`](crate::types::TaxExemptionDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TaxExemptionDetailsBuilder {
    pub(crate) tax_exemptions: ::std::option::Option<::std::vec::Vec<crate::types::TaxExemption>>,
    pub(crate) heritage_obtained_details: ::std::option::Option<bool>,
    pub(crate) heritage_obtained_parent_entity: ::std::option::Option<::std::string::String>,
    pub(crate) heritage_obtained_reason: ::std::option::Option<::std::string::String>,
}
impl TaxExemptionDetailsBuilder {
    /// Appends an item to `tax_exemptions`.
    ///
    /// To override the contents of this collection use [`set_tax_exemptions`](Self::set_tax_exemptions).
    ///
    /// <p>Tax exemptions.</p>
    pub fn tax_exemptions(mut self, input: crate::types::TaxExemption) -> Self {
        let mut v = self.tax_exemptions.unwrap_or_default();
        v.push(input);
        self.tax_exemptions = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tax exemptions.</p>
    pub fn set_tax_exemptions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::TaxExemption>>) -> Self {
        self.tax_exemptions = input;
        self
    }
    /// <p>Tax exemptions.</p>
    pub fn get_tax_exemptions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::TaxExemption>> {
        &self.tax_exemptions
    }
    /// <p>The indicator if the tax exemption is inherited from the consolidated billing family management account.</p>
    pub fn heritage_obtained_details(mut self, input: bool) -> Self {
        self.heritage_obtained_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>The indicator if the tax exemption is inherited from the consolidated billing family management account.</p>
    pub fn set_heritage_obtained_details(mut self, input: ::std::option::Option<bool>) -> Self {
        self.heritage_obtained_details = input;
        self
    }
    /// <p>The indicator if the tax exemption is inherited from the consolidated billing family management account.</p>
    pub fn get_heritage_obtained_details(&self) -> &::std::option::Option<bool> {
        &self.heritage_obtained_details
    }
    /// <p>The consolidated billing family management account the tax exemption inherited from.</p>
    pub fn heritage_obtained_parent_entity(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.heritage_obtained_parent_entity = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The consolidated billing family management account the tax exemption inherited from.</p>
    pub fn set_heritage_obtained_parent_entity(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.heritage_obtained_parent_entity = input;
        self
    }
    /// <p>The consolidated billing family management account the tax exemption inherited from.</p>
    pub fn get_heritage_obtained_parent_entity(&self) -> &::std::option::Option<::std::string::String> {
        &self.heritage_obtained_parent_entity
    }
    /// <p>The reason of the heritage inheritance.</p>
    pub fn heritage_obtained_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.heritage_obtained_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason of the heritage inheritance.</p>
    pub fn set_heritage_obtained_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.heritage_obtained_reason = input;
        self
    }
    /// <p>The reason of the heritage inheritance.</p>
    pub fn get_heritage_obtained_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.heritage_obtained_reason
    }
    /// Consumes the builder and constructs a [`TaxExemptionDetails`](crate::types::TaxExemptionDetails).
    pub fn build(self) -> crate::types::TaxExemptionDetails {
        crate::types::TaxExemptionDetails {
            tax_exemptions: self.tax_exemptions,
            heritage_obtained_details: self.heritage_obtained_details,
            heritage_obtained_parent_entity: self.heritage_obtained_parent_entity,
            heritage_obtained_reason: self.heritage_obtained_reason,
        }
    }
}
