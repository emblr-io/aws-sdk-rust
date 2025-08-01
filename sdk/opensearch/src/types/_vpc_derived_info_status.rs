// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Status of the VPC options for a specified domain.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct VpcDerivedInfoStatus {
    /// <p>The VPC options for the specified domain.</p>
    pub options: ::std::option::Option<crate::types::VpcDerivedInfo>,
    /// <p>The status of the VPC options for the specified domain.</p>
    pub status: ::std::option::Option<crate::types::OptionStatus>,
}
impl VpcDerivedInfoStatus {
    /// <p>The VPC options for the specified domain.</p>
    pub fn options(&self) -> ::std::option::Option<&crate::types::VpcDerivedInfo> {
        self.options.as_ref()
    }
    /// <p>The status of the VPC options for the specified domain.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OptionStatus> {
        self.status.as_ref()
    }
}
impl VpcDerivedInfoStatus {
    /// Creates a new builder-style object to manufacture [`VpcDerivedInfoStatus`](crate::types::VpcDerivedInfoStatus).
    pub fn builder() -> crate::types::builders::VpcDerivedInfoStatusBuilder {
        crate::types::builders::VpcDerivedInfoStatusBuilder::default()
    }
}

/// A builder for [`VpcDerivedInfoStatus`](crate::types::VpcDerivedInfoStatus).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct VpcDerivedInfoStatusBuilder {
    pub(crate) options: ::std::option::Option<crate::types::VpcDerivedInfo>,
    pub(crate) status: ::std::option::Option<crate::types::OptionStatus>,
}
impl VpcDerivedInfoStatusBuilder {
    /// <p>The VPC options for the specified domain.</p>
    /// This field is required.
    pub fn options(mut self, input: crate::types::VpcDerivedInfo) -> Self {
        self.options = ::std::option::Option::Some(input);
        self
    }
    /// <p>The VPC options for the specified domain.</p>
    pub fn set_options(mut self, input: ::std::option::Option<crate::types::VpcDerivedInfo>) -> Self {
        self.options = input;
        self
    }
    /// <p>The VPC options for the specified domain.</p>
    pub fn get_options(&self) -> &::std::option::Option<crate::types::VpcDerivedInfo> {
        &self.options
    }
    /// <p>The status of the VPC options for the specified domain.</p>
    /// This field is required.
    pub fn status(mut self, input: crate::types::OptionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The status of the VPC options for the specified domain.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::OptionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The status of the VPC options for the specified domain.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::OptionStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`VpcDerivedInfoStatus`](crate::types::VpcDerivedInfoStatus).
    pub fn build(self) -> crate::types::VpcDerivedInfoStatus {
        crate::types::VpcDerivedInfoStatus {
            options: self.options,
            status: self.status,
        }
    }
}
