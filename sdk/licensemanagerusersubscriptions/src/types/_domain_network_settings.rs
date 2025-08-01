// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains network settings for the Active Directory domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DomainNetworkSettings {
    /// <p>Contains a list of subnets that apply for the Active Directory domain.</p>
    pub subnets: ::std::vec::Vec<::std::string::String>,
}
impl DomainNetworkSettings {
    /// <p>Contains a list of subnets that apply for the Active Directory domain.</p>
    pub fn subnets(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.subnets.deref()
    }
}
impl DomainNetworkSettings {
    /// Creates a new builder-style object to manufacture [`DomainNetworkSettings`](crate::types::DomainNetworkSettings).
    pub fn builder() -> crate::types::builders::DomainNetworkSettingsBuilder {
        crate::types::builders::DomainNetworkSettingsBuilder::default()
    }
}

/// A builder for [`DomainNetworkSettings`](crate::types::DomainNetworkSettings).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DomainNetworkSettingsBuilder {
    pub(crate) subnets: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl DomainNetworkSettingsBuilder {
    /// Appends an item to `subnets`.
    ///
    /// To override the contents of this collection use [`set_subnets`](Self::set_subnets).
    ///
    /// <p>Contains a list of subnets that apply for the Active Directory domain.</p>
    pub fn subnets(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.subnets.unwrap_or_default();
        v.push(input.into());
        self.subnets = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains a list of subnets that apply for the Active Directory domain.</p>
    pub fn set_subnets(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.subnets = input;
        self
    }
    /// <p>Contains a list of subnets that apply for the Active Directory domain.</p>
    pub fn get_subnets(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.subnets
    }
    /// Consumes the builder and constructs a [`DomainNetworkSettings`](crate::types::DomainNetworkSettings).
    /// This method will fail if any of the following fields are not set:
    /// - [`subnets`](crate::types::builders::DomainNetworkSettingsBuilder::subnets)
    pub fn build(self) -> ::std::result::Result<crate::types::DomainNetworkSettings, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DomainNetworkSettings {
            subnets: self.subnets.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "subnets",
                    "subnets was not specified but it is required when building DomainNetworkSettings",
                )
            })?,
        })
    }
}
