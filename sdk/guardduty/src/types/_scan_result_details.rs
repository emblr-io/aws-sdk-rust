// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the result of the scan.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ScanResultDetails {
    /// <p>An enum value representing possible scan results.</p>
    pub scan_result: ::std::option::Option<crate::types::ScanResult>,
}
impl ScanResultDetails {
    /// <p>An enum value representing possible scan results.</p>
    pub fn scan_result(&self) -> ::std::option::Option<&crate::types::ScanResult> {
        self.scan_result.as_ref()
    }
}
impl ScanResultDetails {
    /// Creates a new builder-style object to manufacture [`ScanResultDetails`](crate::types::ScanResultDetails).
    pub fn builder() -> crate::types::builders::ScanResultDetailsBuilder {
        crate::types::builders::ScanResultDetailsBuilder::default()
    }
}

/// A builder for [`ScanResultDetails`](crate::types::ScanResultDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ScanResultDetailsBuilder {
    pub(crate) scan_result: ::std::option::Option<crate::types::ScanResult>,
}
impl ScanResultDetailsBuilder {
    /// <p>An enum value representing possible scan results.</p>
    pub fn scan_result(mut self, input: crate::types::ScanResult) -> Self {
        self.scan_result = ::std::option::Option::Some(input);
        self
    }
    /// <p>An enum value representing possible scan results.</p>
    pub fn set_scan_result(mut self, input: ::std::option::Option<crate::types::ScanResult>) -> Self {
        self.scan_result = input;
        self
    }
    /// <p>An enum value representing possible scan results.</p>
    pub fn get_scan_result(&self) -> &::std::option::Option<crate::types::ScanResult> {
        &self.scan_result
    }
    /// Consumes the builder and constructs a [`ScanResultDetails`](crate::types::ScanResultDetails).
    pub fn build(self) -> crate::types::ScanResultDetails {
        crate::types::ScanResultDetails {
            scan_result: self.scan_result,
        }
    }
}
