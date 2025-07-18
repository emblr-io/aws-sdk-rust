// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The properties of a billing group.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BillingGroupProperties {
    /// <p>The description of the billing group.</p>
    pub billing_group_description: ::std::option::Option<::std::string::String>,
}
impl BillingGroupProperties {
    /// <p>The description of the billing group.</p>
    pub fn billing_group_description(&self) -> ::std::option::Option<&str> {
        self.billing_group_description.as_deref()
    }
}
impl BillingGroupProperties {
    /// Creates a new builder-style object to manufacture [`BillingGroupProperties`](crate::types::BillingGroupProperties).
    pub fn builder() -> crate::types::builders::BillingGroupPropertiesBuilder {
        crate::types::builders::BillingGroupPropertiesBuilder::default()
    }
}

/// A builder for [`BillingGroupProperties`](crate::types::BillingGroupProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BillingGroupPropertiesBuilder {
    pub(crate) billing_group_description: ::std::option::Option<::std::string::String>,
}
impl BillingGroupPropertiesBuilder {
    /// <p>The description of the billing group.</p>
    pub fn billing_group_description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.billing_group_description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The description of the billing group.</p>
    pub fn set_billing_group_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.billing_group_description = input;
        self
    }
    /// <p>The description of the billing group.</p>
    pub fn get_billing_group_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.billing_group_description
    }
    /// Consumes the builder and constructs a [`BillingGroupProperties`](crate::types::BillingGroupProperties).
    pub fn build(self) -> crate::types::BillingGroupProperties {
        crate::types::BillingGroupProperties {
            billing_group_description: self.billing_group_description,
        }
    }
}
