// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTaxInheritanceInput {}
impl GetTaxInheritanceInput {
    /// Creates a new builder-style object to manufacture [`GetTaxInheritanceInput`](crate::operation::get_tax_inheritance::GetTaxInheritanceInput).
    pub fn builder() -> crate::operation::get_tax_inheritance::builders::GetTaxInheritanceInputBuilder {
        crate::operation::get_tax_inheritance::builders::GetTaxInheritanceInputBuilder::default()
    }
}

/// A builder for [`GetTaxInheritanceInput`](crate::operation::get_tax_inheritance::GetTaxInheritanceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTaxInheritanceInputBuilder {}
impl GetTaxInheritanceInputBuilder {
    /// Consumes the builder and constructs a [`GetTaxInheritanceInput`](crate::operation::get_tax_inheritance::GetTaxInheritanceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_tax_inheritance::GetTaxInheritanceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_tax_inheritance::GetTaxInheritanceInput {})
    }
}
