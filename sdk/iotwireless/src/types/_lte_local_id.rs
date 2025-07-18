// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>LTE local identification (local ID) information.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LteLocalId {
    /// <p>Physical cell ID.</p>
    pub pci: i32,
    /// <p>Evolved universal terrestrial radio access (E-UTRA) absolute radio frequency channel number (FCN).</p>
    pub earfcn: i32,
}
impl LteLocalId {
    /// <p>Physical cell ID.</p>
    pub fn pci(&self) -> i32 {
        self.pci
    }
    /// <p>Evolved universal terrestrial radio access (E-UTRA) absolute radio frequency channel number (FCN).</p>
    pub fn earfcn(&self) -> i32 {
        self.earfcn
    }
}
impl LteLocalId {
    /// Creates a new builder-style object to manufacture [`LteLocalId`](crate::types::LteLocalId).
    pub fn builder() -> crate::types::builders::LteLocalIdBuilder {
        crate::types::builders::LteLocalIdBuilder::default()
    }
}

/// A builder for [`LteLocalId`](crate::types::LteLocalId).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LteLocalIdBuilder {
    pub(crate) pci: ::std::option::Option<i32>,
    pub(crate) earfcn: ::std::option::Option<i32>,
}
impl LteLocalIdBuilder {
    /// <p>Physical cell ID.</p>
    /// This field is required.
    pub fn pci(mut self, input: i32) -> Self {
        self.pci = ::std::option::Option::Some(input);
        self
    }
    /// <p>Physical cell ID.</p>
    pub fn set_pci(mut self, input: ::std::option::Option<i32>) -> Self {
        self.pci = input;
        self
    }
    /// <p>Physical cell ID.</p>
    pub fn get_pci(&self) -> &::std::option::Option<i32> {
        &self.pci
    }
    /// <p>Evolved universal terrestrial radio access (E-UTRA) absolute radio frequency channel number (FCN).</p>
    /// This field is required.
    pub fn earfcn(mut self, input: i32) -> Self {
        self.earfcn = ::std::option::Option::Some(input);
        self
    }
    /// <p>Evolved universal terrestrial radio access (E-UTRA) absolute radio frequency channel number (FCN).</p>
    pub fn set_earfcn(mut self, input: ::std::option::Option<i32>) -> Self {
        self.earfcn = input;
        self
    }
    /// <p>Evolved universal terrestrial radio access (E-UTRA) absolute radio frequency channel number (FCN).</p>
    pub fn get_earfcn(&self) -> &::std::option::Option<i32> {
        &self.earfcn
    }
    /// Consumes the builder and constructs a [`LteLocalId`](crate::types::LteLocalId).
    /// This method will fail if any of the following fields are not set:
    /// - [`pci`](crate::types::builders::LteLocalIdBuilder::pci)
    /// - [`earfcn`](crate::types::builders::LteLocalIdBuilder::earfcn)
    pub fn build(self) -> ::std::result::Result<crate::types::LteLocalId, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::LteLocalId {
            pci: self.pci.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pci",
                    "pci was not specified but it is required when building LteLocalId",
                )
            })?,
            earfcn: self.earfcn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "earfcn",
                    "earfcn was not specified but it is required when building LteLocalId",
                )
            })?,
        })
    }
}
