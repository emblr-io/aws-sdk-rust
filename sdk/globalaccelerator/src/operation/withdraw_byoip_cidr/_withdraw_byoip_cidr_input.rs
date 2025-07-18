// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct WithdrawByoipCidrInput {
    /// <p>The address range, in CIDR notation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/using-byoip.html">Bring your own IP addresses (BYOIP)</a> in the Global Accelerator Developer Guide.</p>
    pub cidr: ::std::option::Option<::std::string::String>,
}
impl WithdrawByoipCidrInput {
    /// <p>The address range, in CIDR notation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/using-byoip.html">Bring your own IP addresses (BYOIP)</a> in the Global Accelerator Developer Guide.</p>
    pub fn cidr(&self) -> ::std::option::Option<&str> {
        self.cidr.as_deref()
    }
}
impl WithdrawByoipCidrInput {
    /// Creates a new builder-style object to manufacture [`WithdrawByoipCidrInput`](crate::operation::withdraw_byoip_cidr::WithdrawByoipCidrInput).
    pub fn builder() -> crate::operation::withdraw_byoip_cidr::builders::WithdrawByoipCidrInputBuilder {
        crate::operation::withdraw_byoip_cidr::builders::WithdrawByoipCidrInputBuilder::default()
    }
}

/// A builder for [`WithdrawByoipCidrInput`](crate::operation::withdraw_byoip_cidr::WithdrawByoipCidrInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct WithdrawByoipCidrInputBuilder {
    pub(crate) cidr: ::std::option::Option<::std::string::String>,
}
impl WithdrawByoipCidrInputBuilder {
    /// <p>The address range, in CIDR notation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/using-byoip.html">Bring your own IP addresses (BYOIP)</a> in the Global Accelerator Developer Guide.</p>
    /// This field is required.
    pub fn cidr(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cidr = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The address range, in CIDR notation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/using-byoip.html">Bring your own IP addresses (BYOIP)</a> in the Global Accelerator Developer Guide.</p>
    pub fn set_cidr(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cidr = input;
        self
    }
    /// <p>The address range, in CIDR notation.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/global-accelerator/latest/dg/using-byoip.html">Bring your own IP addresses (BYOIP)</a> in the Global Accelerator Developer Guide.</p>
    pub fn get_cidr(&self) -> &::std::option::Option<::std::string::String> {
        &self.cidr
    }
    /// Consumes the builder and constructs a [`WithdrawByoipCidrInput`](crate::operation::withdraw_byoip_cidr::WithdrawByoipCidrInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::withdraw_byoip_cidr::WithdrawByoipCidrInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::withdraw_byoip_cidr::WithdrawByoipCidrInput { cidr: self.cidr })
    }
}
